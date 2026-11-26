import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createFinding, type Finding } from "../src/finding.js";
import { matchIgnoreEntry } from "../src/ignore.js";
import { inventory, looksLikeRequirements } from "../src/inventory.js";
import {
  MAX_DEPENDENCIES_PER_FILE,
  parseLockfile,
  parseRequirements,
  runSca,
  type HttpClient,
} from "../src/sca.js";
import { scanProject } from "../src/scan.js";
import { redactSecretsInText, scanSecrets } from "../src/secrets.js";
import { crossEngineDedupe, mergeScaFindings } from "../src/external/merge.js";
import { runOsvScanner } from "../src/external/osvScanner.js";
import { FIXTURES, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("sca-hardening");

afterAll(() => cleanup(temp));

/**
 * `count` distinct pins, one per line, 7 bytes each so that 135k of them stay
 * under the 1 MB inventory limit (as the review proof of concept did).
 */
function manyPins(count: number): string {
  const lines = new Array<string>(count);
  for (let index = 0; index < count; index += 1) {
    const name = (index % 46656).toString(36).padStart(3, "0");
    lines[index] = `${name}==${Math.floor(index / 46656)}`;
  }
  return `${lines.join("\n")}\n`;
}

// Split so that this test file never contains a complete credential.
const AWS_KEY = ["AKIA", "Q4ZT7XWPL3NVB2KD"].join("");
const PRIVATE_KEY_HEADER = ["-----BEGIN RSA ", "PRIVATE KEY-----"].join("");
const GITHUB_TOKEN = ["ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"].join("");

describe("large dependency files never abort the scan", () => {
  it("parses an -r include with more pins than a call can take as arguments", () => {
    const root = path.join(temp, "big-include");
    writeFile(root, "requirements.txt", "-r deps.lst\n");
    writeFile(root, "deps.lst", manyPins(150_000));
    const parsed = parseRequirements("-r deps.lst\n", "requirements.txt", { root });
    expect(parsed.packages).toHaveLength(150_000);
    expect(parsed.packages[0]?.file).toBe("deps.lst");
  });

  it("caps the dependencies of one file and says so, instead of overflowing the stack", async () => {
    const root = path.join(temp, "big-file");
    writeFile(root, "requirements.txt", manyPins(135_000));
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    expect(result.packages).toHaveLength(MAX_DEPENDENCIES_PER_FILE);
    const cap = result.warnings.filter((warning) => warning.includes("more than 50000 dependencies"));
    expect(cap).toHaveLength(1);
    expect(cap[0]).toContain("requirements.txt");
    expect(cap[0]).toContain("85000 further entries were not checked");
  });

  it("completes a whole scan of the include and single-file cases", async () => {
    const root = path.join(temp, "big-scan");
    writeFile(root, "requirements.txt", "-r deps.lst\n");
    writeFile(root, "deps.lst", manyPins(150_000));
    writeFile(root, "svc/requirements.txt", manyPins(135_000));
    const result = await scanProject({
      root,
      out: path.join(temp, "big-scan-out"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const warnings = result.coverage.warnings.join("\n");
    expect(warnings).toContain("deps.lst: more than 50000 dependencies");
    expect(warnings).toContain("svc/requirements.txt: more than 50000 dependencies");
  });

  it("turns an exception in one dependency file into a warning and keeps going", async () => {
    const root = path.join(temp, "one-bad-file");
    writeFile(root, "a/requirements.txt", "requests==2.19.0\n");
    writeFile(root, "b/requirements.txt", "flask==2.0.0\n");
    const result = await runSca({
      root,
      inventory: inventory(root),
      offline: true,
      parseLockfile: (relPath, content, options) => {
        if (relPath.startsWith("a/")) throw new RangeError("Maximum call stack size exceeded");
        return parseLockfile(relPath, content, options);
      },
    });
    expect(result.packages.map((pkg) => `${pkg.file}:${pkg.name}`)).toEqual([
      "b/requirements.txt:flask",
    ]);
    expect(result.warnings).toContain(
      "a/requirements.txt: dependency file could not be parsed and was skipped (Maximum call stack size exceeded)",
    );
  });
});

describe("requirements-style files are classified by content, not only by name", () => {
  it("recognises requirement specifiers and pip options, and rejects prose", () => {
    expect(
      looksLikeRequirements(
        [
          "# pinned",
          "-r base.txt",
          "--index-url https://pypi.example.com/simple",
          "Django==3.2.0 \\",
          "    --hash=sha256:1111",
          'requests>=2.19.0 ; python_version < "3.9"',
          "flask[async]==2.0.0",
          "mypkg @ https://example.invalid/pkg.whl",
          "git+https://github.com/example/repo.git",
          "pytest",
        ].join("\n"),
      ),
    ).toBe(true);
    expect(looksLikeRequirements("# only a comment\n\n")).toBe(true);
    expect(
      looksLikeRequirements(
        [
          "Deployment notes for the staging cluster.",
          'password = "not-a-requirement"',
          "AWS_ACCESS_KEY_ID=abc",
          "-----BEGIN CERTIFICATE-----",
          "requests==2.19.0",
        ].join("\n"),
      ),
    ).toBe(false);
  });

  it("treats prose in requirements/ as an ordinary text file without SCA noise", async () => {
    const root = path.join(temp, "prose");
    writeFile(root, "requirements/dev.txt", "pytest==8.0.0\nruff==0.4.0\n");
    writeFile(
      root,
      "requirements/notes.txt",
      "Remember to rotate the deploy key.\nAsk ops before upgrading.\nflask (maybe) next sprint\n",
    );
    writeFile(root, "old-requirements.txt", "These are no longer used.\nSee the wiki page.\n");
    writeFile(root, "docs/pylock.dev.toml", 'title = "not a lockfile"\n');
    writeFile(root, "pylock.ci.toml", 'lock-version = "1.0"\ncreated-by = "test"\n');
    const inv = inventory(root);
    const byPath = new Map(inv.files.map((file) => [file.relPath, file]));
    expect(inv.lockfiles.map((file) => file.relPath).sort()).toEqual([
      "pylock.ci.toml",
      "requirements/dev.txt",
    ]);
    for (const rel of ["requirements/notes.txt", "old-requirements.txt", "docs/pylock.dev.toml"]) {
      expect(byPath.get(rel)?.isLockfile, rel).toBe(false);
      expect(byPath.get(rel)?.scannable, rel).toBe(true);
    }
    const result = await runSca({ root, inventory: inv, offline: true });
    expect(result.packages.map((pkg) => pkg.file)).toEqual([
      "requirements/dev.txt",
      "requirements/dev.txt",
    ]);
    expect(result.warnings.join("\n")).not.toMatch(/notes\.txt|old-requirements|pylock\.dev/);
  });
});

describe("secret detection in dependency files", () => {
  const planted = [`AWS_ACCESS_KEY_ID=${AWS_KEY}`, PRIVATE_KEY_HEADER, "MIIEowIBAAKCAQEAx", ""].join(
    "\n",
  );

  function secretsIn(root: string): Finding[] {
    return scanSecrets(inventory(root).files).findings;
  }

  it("finds secrets in every file the old name-based lockfile rule hid", () => {
    const root = path.join(temp, "hidden-secrets");
    const names = [
      "requirements/notes.txt",
      "requirements/deploy-credentials.txt",
      "old-requirements.txt",
      "requirements-secrets.txt",
      "docs/pylock.dev.toml",
    ];
    for (const name of names) {
      writeFile(root, name, `${planted}password = "Tr0ub4dor&3xKcd9Zq"\n`);
    }
    const findings = secretsIn(root);
    for (const name of names) {
      const rules = findings.filter((f) => f.file === name).map((f) => f.ruleId).sort();
      expect(rules, name).toEqual([
        "secret-aws-access-key",
        "secret-generic-assignment",
        "secret-private-key",
      ]);
    }
    expect(JSON.stringify(findings)).not.toContain(AWS_KEY);
    expect(JSON.stringify(findings)).not.toContain("Tr0ub4dor");
  });

  it("finds planted keys in real requirements files and manifests", () => {
    const root = path.join(temp, "planted-handwritten");
    const files: Record<string, string> = {
      "requirements.txt": "requests==2.33.0\n",
      "requirements/base.txt": "jinja2==3.1.6\nmarkupsafe==3.0.2\n",
      "go.mod": "module example.com/app\n\ngo 1.22\n",
      "pyproject.toml": '[project]\nname = "app"\nversion = "1.0.0"\n',
      "package.json": '{ "name": "app", "version": "1.0.0" }\n',
      Pipfile: '[packages]\nrequests = "==2.33.0"\n',
    };
    for (const [name, content] of Object.entries(files)) {
      writeFile(root, name, `${content}${name.endsWith(".json") ? "" : `# ${AWS_KEY}\n`}`);
    }
    writeFile(root, "package.json", `{ "name": "app", "awsKey": "${AWS_KEY}" }\n`);
    const inv = inventory(root);
    // Still dependency sources for SCA.
    expect(inv.lockfiles.map((file) => file.relPath).sort()).toEqual([
      "go.mod",
      "requirements.txt",
      "requirements/base.txt",
    ]);
    const found = scanSecrets(inv.files).findings;
    for (const name of Object.keys(files)) {
      expect(
        found.filter((f) => f.file === name).map((f) => f.ruleId),
        name,
      ).toEqual(["secret-aws-access-key"]);
    }
  });

  it("finds planted high-confidence secrets in every generated lockfile type", () => {
    const root = path.join(temp, "planted-generated");
    const lockfiles = [
      "package-lock.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "poetry.lock",
      "uv.lock",
      "pdm.lock",
      "Pipfile.lock",
      "pylock.toml",
      "pylock.dev.toml",
      "go.sum",
      "packages.lock.json",
      "Cargo.lock",
      "composer.lock",
    ];
    for (const name of lockfiles) {
      const head = name === "pylock.dev.toml" ? 'lock-version = "1.0"\n' : "";
      writeFile(root, `${name.replace(/\W/g, "_")}/${name}`, `${head}${planted}${GITHUB_TOKEN}\n`);
    }
    const inv = inventory(root);
    expect(inv.stats.partialFiles).toBe(lockfiles.length);
    expect(inv.files.every((file) => file.isLockfile && !file.scannable)).toBe(true);
    const found = scanSecrets(inv.files).findings;
    for (const name of lockfiles) {
      const rules = found
        .filter((f) => path.posix.basename(f.file) === name)
        .map((f) => f.ruleId)
        .sort();
      expect(rules, name).toEqual([
        "secret-aws-access-key",
        "secret-github-token",
        "secret-private-key",
      ]);
    }
    expect(JSON.stringify(found)).not.toContain(AWS_KEY);
    expect(JSON.stringify(found)).not.toContain(GITHUB_TOKEN);
  });

  it("does not run the generic assignment heuristic on generated lockfiles", () => {
    const root = path.join(temp, "generated-generic");
    writeFile(
      root,
      "uv.lock",
      'version = 1\n\n[[package]]\nname = "token"\nversion = "1.0"\nsecret = "c29tZS1yYW5kb20tbG9va2luZy1zdHJpbmc"\n',
    );
    expect(secretsIn(root)).toEqual([]);
  });

  it("reports no secret in the real lockfile fixtures (no hash false positives)", () => {
    for (const tree of ["clean/sca", "vulnerable/sca"]) {
      const inv = inventory(path.join(FIXTURES, tree));
      const generated = inv.files.filter((file) => file.isLockfile && !file.scannable);
      expect(generated.length).toBeGreaterThanOrEqual(5);
      const found = scanSecrets(inv.files).findings;
      expect(
        found.map((f) => `${f.file}:${f.startLine} ${f.ruleId}`),
        tree,
      ).toEqual([]);
    }
  });

  it("stays quiet on hash-heavy lockfile content", () => {
    const root = path.join(temp, "hash-heavy");
    const hex = (seed: number, length: number): string => {
      let out = "";
      let state = seed;
      while (out.length < length) {
        state = (state * 1103515245 + 12345) & 0x7fffffff;
        out += state.toString(16);
      }
      return out.slice(0, length);
    };
    const base64 = (seed: number): string =>
      Buffer.from(hex(seed, 128), "hex").toString("base64");
    const npm: Record<string, unknown> = {};
    const pins: string[] = [];
    const sums: string[] = [];
    for (let index = 0; index < 2000; index += 1) {
      npm[`node_modules/pkg${index}`] = {
        version: "1.0.0",
        resolved: `https://registry.npmjs.org/pkg${index}/-/pkg${index}-1.0.0.tgz`,
        integrity: `sha512-${base64(index + 1)}`,
      };
      pins.push(`pkg${index}==1.0.0 \\`, `    --hash=sha256:${hex(index + 7, 64)}`);
      sums.push(`example.com/pkg${index} v1.0.0 h1:${base64(index + 9).slice(0, 43)}=`);
    }
    writeFile(root, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: npm }, null, 2));
    writeFile(root, "requirements.txt", `${pins.join("\n")}\n`);
    writeFile(root, "go.sum", `${sums.join("\n")}\n`);
    expect(secretsIn(root)).toEqual([]);
  });

  it("reports credentials embedded in an index URL, redacted", () => {
    const root = path.join(temp, "index-url");
    const password = ["pypi-", "AgEIcHlwaS5vcmcCJDk4"].join("");
    writeFile(
      root,
      "requirements.txt",
      [
        `--index-url https://deploy:${password}@pypi.internal.example.org/simple`,
        "--extra-index-url https://${PIP_USER}:${PIP_PASSWORD}@pypi.internal.example.org/simple",
        "--find-links https://user:password@mirror.invalid/wheels",
        "--trusted-host pypi.internal.example.org:8443",
        "requests==2.33.0",
        "",
      ].join("\n"),
    );
    writeFile(
      root,
      "poetry.lock",
      `[[package]]\nname = "x"\nversion = "1"\n\n[package.source]\nurl = "https://ci:${password}@pypi.internal.example.org/simple"\n`,
    );
    const found = secretsIn(root);
    expect(found.map((f) => `${f.file}:${f.startLine} ${f.ruleId}`).sort()).toEqual([
      "poetry.lock:6 secret-url-credentials",
      "requirements.txt:1 secret-url-credentials",
    ]);
    expect(JSON.stringify(found)).not.toContain(password);
    const requirement = found.find((f) => f.file === "requirements.txt");
    // Only the first 2 and last 2 characters of a long secret stay visible.
    expect(requirement?.evidence).toContain("https://deploy:py*");
    expect(requirement?.evidence).toContain("@pypi.internal.example.org/simple");
    expect(redactSecretsInText(`pip install -i https://deploy:${password}@host/simple`)).not.toContain(
      password,
    );
  });

  it("redacts every secret on a line, not only the one being reported", () => {
    const root = path.join(temp, "two-on-a-line");
    writeFile(root, "settings.txt", `key=${AWS_KEY} token=${GITHUB_TOKEN}\n`);
    const found = secretsIn(root);
    expect(found).toHaveLength(2);
    expect(JSON.stringify(found)).not.toContain(AWS_KEY);
    expect(JSON.stringify(found)).not.toContain(GITHUB_TOKEN);
  });

  it("counts partially analysed files truthfully in the scan summary", async () => {
    const root = path.join(temp, "partial-counts");
    writeFile(root, "app.py", "print('hello')\n");
    writeFile(root, "requirements.txt", "requests==2.33.0\n");
    writeFile(root, "uv.lock", 'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.33.0"\n');
    writeFile(root, "go.sum", "example.com/a v1.0.0 h1:abc=\n");
    const out = path.join(temp, "partial-counts-out");
    const result = await scanProject({
      root,
      out,
      offline: true,
      engines: ["builtin"],
      formats: ["md", "json"],
      lang: "en",
    });
    expect(result.coverage.stats.scannedFiles).toBe(4);
    expect(result.coverage.stats.partialFiles).toBe(2);
    expect(result.coverage.stats.skippedFiles).toBe(0);
    const engines = new Map(result.coverage.scannedFiles.map((file) => [file.path, file.engines]));
    expect(engines.get("requirements.txt")).toEqual(["sca", "builtin-secrets"]);
    expect(engines.get("uv.lock")).toEqual(["sca", "builtin-secrets:high-confidence"]);
    expect(engines.get("app.py")).toEqual(["builtin-secrets", "builtin-rules"]);
    const report = fs
      .readdirSync(result.runDir)
      .filter((name) => name.endsWith(".md"))
      .map((name) => fs.readFileSync(path.join(result.runDir, name), "utf8"))
      .join("\n");
    expect(report).toMatch(/Scanned files: 4 \(2 partially/);
  });
});

describe("osv-scanner results for -r includes", () => {
  const advisory = {
    id: "GHSA-x84v-xcm2-53pg",
    summary: "Insufficiently protected credentials in Requests",
    aliases: ["CVE-2018-18074", "PYSEC-2018-28"],
    affected: [
      {
        package: { ecosystem: "PyPI", name: "requests" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.20.0" }] }],
      },
    ],
  };
  const http: HttpClient = {
    async postJson(_url, body) {
      const queries = (body as { queries: Array<{ package: { name: string } }> }).queries;
      return {
        results: queries.map((query) =>
          query.package.name === "requests" ? { vulns: [{ id: advisory.id }] } : {},
        ),
      };
    },
    async getJson() {
      return advisory;
    },
  };

  it("places the finding on the included file so it merges with the built-in one", async () => {
    const root = path.join(temp, "osv-include");
    writeFile(root, "requirements.txt", "-r requirements/base.txt\nflask==3.1.3\n");
    writeFile(root, "requirements/base.txt", "# base\nrequests==2.19.0\n");
    // Shape of real OSV-Scanner output: pins reached through `-r` are listed
    // under the top-level requirements file, which is the only source.
    const toolDir = path.join(temp, "osv-include-bin");
    fs.mkdirSync(toolDir, { recursive: true });
    fs.writeFileSync(
      path.join(toolDir, "report.json"),
      JSON.stringify({
        results: [
          {
            source: { path: path.join(root, "requirements.txt"), type: "lockfile" },
            packages: [
              {
                package: { name: "requests", version: "2.19.0", ecosystem: "PyPI" },
                vulnerabilities: [advisory],
                groups: [{ ids: [advisory.id], aliases: advisory.aliases, max_severity: "6.1" }],
              },
            ],
          },
        ],
      }),
    );
    const tool = path.join(toolDir, "osv-scanner.cjs");
    fs.writeFileSync(
      tool,
      [
        "#!/usr/bin/env node",
        "const fs = require('fs');",
        "const path = require('path');",
        "fs.writeSync(1, fs.readFileSync(path.join(__dirname, 'report.json')));",
        "process.exit(1);",
        "",
      ].join("\n"),
    );
    fs.chmodSync(tool, 0o755);

    const external = await runOsvScanner({ root, toolPath: tool, timeoutMs: 10_000 });
    expect(external.ok).toBe(true);
    expect(external.reportedFiles).toEqual(["requirements.txt"]);
    expect(external.findings.map((f) => `${f.file}:${f.startLine}`)).toEqual([
      "requirements/base.txt:2",
    ]);

    // Same wiring as scanProject: files the tool reported are skipped by the
    // built-in engine, which still reads the included file on its own.
    const builtin = await runSca({
      root,
      inventory: inventory(root),
      http,
      skipLockfiles: external.reportedFiles,
    });
    expect(builtin.findings.map((f) => `${f.file}:${f.startLine}`)).toEqual([
      "requirements/base.txt:2",
    ]);
    const merged = mergeScaFindings(builtin.findings, external.findings);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.file).toBe("requirements/base.txt");
    expect(merged[0]?.provenance.engines).toEqual(
      expect.arrayContaining(["osv", "osv-scanner"]),
    );
  });
});

describe("merged SCA findings stay self-consistent", () => {
  const sca = (overrides: Record<string, unknown>): Finding =>
    createFinding({
      ruleId: `sca-${String(overrides.advisoryId).toLowerCase()}`,
      title: "requests advisory",
      category: "sca",
      severity: "medium",
      confidence: "high",
      file: "requirements.txt",
      startLine: 1,
      evidence: "requests@2.19.0",
      message: "m",
      remediation: "Upgrade requests to the latest stable or vendor-recommended version; confirm the impact before choosing mitigations.",
      package: "requests",
      ecosystem: "PyPI",
      installedVersion: "2.19.0",
      provenance: { engine: "osv" },
      ...overrides,
    } as Parameters<typeof createFinding>[0]);

  it("names the merged fixed version in the remediation text", () => {
    const withFix = sca({
      advisoryId: "PYSEC-2018-28",
      aliases: ["CVE-2018-18074"],
      fixedVersion: "2.20.0",
      remediation: "Upgrade requests to 2.20.0 or later; rerun the dependency audit and regression tests.",
    });
    const preferredWithoutFix = sca({
      advisoryId: "GHSA-x84v-xcm2-53pg",
      aliases: ["PYSEC-2018-28"],
      provenance: { engine: "osv-scanner" },
    });
    const [merged] = mergeScaFindings([withFix], [preferredWithoutFix]);
    expect(merged?.advisoryId).toBe("GHSA-x84v-xcm2-53pg");
    expect(merged?.fixedVersion).toBe("2.20.0");
    expect(merged?.remediation).toContain("2.20.0");
  });

  it("takes fixed version and text from the same side when the two disagree", () => {
    const builtin = sca({
      advisoryId: "PYSEC-2018-28",
      aliases: ["GHSA-x84v-xcm2-53pg"],
      fixedVersion: "2.20.0",
      remediation: "Upgrade requests to 2.20.0 or later; rerun the dependency audit and regression tests.",
    });
    const external = sca({
      advisoryId: "GHSA-x84v-xcm2-53pg",
      aliases: ["PYSEC-2018-28"],
      fixedVersion: "2.31.0",
      remediation: "Upgrade requests to 2.31.0 or later; rerun the dependency audit and regression tests.",
      provenance: { engine: "osv-scanner" },
    });
    for (const [merged] of [
      mergeScaFindings([builtin], [external]),
      mergeScaFindings([external], [builtin]),
    ]) {
      expect(merged?.fixedVersion).toBeDefined();
      expect(merged?.remediation).toContain(String(merged?.fixedVersion));
    }
  });
});

describe("same-engine SAST results on one line", () => {
  const sast = (overrides: Record<string, unknown>): Finding =>
    createFinding({
      ruleId: "py-opengrep-eval",
      title: "eval",
      category: "sast",
      severity: "high",
      confidence: "medium",
      cwe: "CWE-95",
      file: "app.py",
      startLine: 12,
      evidence: "eval(request.args['q'])",
      message: "m",
      remediation: "r",
      provenance: { engine: "opengrep", rule: "py-opengrep-eval" },
      ...overrides,
    } as Parameters<typeof createFinding>[0]);

  it("collapses an Opengrep pattern rule and taint rule into one finding", () => {
    const pattern = sast({});
    const taint = sast({
      ruleId: "py-taint-eval",
      severity: "critical",
      confidence: "high",
      provenance: { engine: "opengrep", rule: "py-taint-eval" },
    });
    const merged = crossEngineDedupe([pattern, taint]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.severity).toBe("critical");
    expect(merged[0]?.confidence).toBe("high");
    expect((merged[0]?.provenance as { rules?: string[] }).rules).toEqual([
      "py-opengrep-eval",
      "py-taint-eval",
    ]);
    expect(merged[0]?.provenance.engines).toEqual(["opengrep"]);
  });

  it("keeps different weaknesses, other lines and distinct secrets apart", () => {
    const pattern = sast({});
    expect(crossEngineDedupe([pattern, sast({ ruleId: "py-taint-x", cwe: "CWE-78" })])).toHaveLength(2);
    expect(
      crossEngineDedupe([pattern, sast({ ruleId: "py-taint-eval", startLine: 40 })]),
    ).toHaveLength(2);
    const secret = (ruleId: string): Finding =>
      sast({
        ruleId,
        category: "secrets",
        cwe: "CWE-798",
        provenance: { engine: "gitleaks", rule: ruleId },
      });
    expect(crossEngineDedupe([secret("aws-access-token"), secret("github-pat")])).toHaveLength(2);
  });

  it("still merges with a built-in hit and keeps all three rule ids", () => {
    const builtin = sast({
      ruleId: "py-eval-dynamic",
      provenance: { engine: "builtin-rules", rule: "py-eval-dynamic" },
    });
    const merged = crossEngineDedupe([
      builtin,
      sast({}),
      sast({ ruleId: "py-taint-eval", provenance: { engine: "opengrep", rule: "py-taint-eval" } }),
    ]);
    expect(merged).toHaveLength(1);
    expect((merged[0]?.provenance as { rules?: string[] }).rules).toEqual([
      "py-eval-dynamic",
      "py-opengrep-eval",
      "py-taint-eval",
    ]);
  });
});

describe("ignore-file rule entries for SCA findings", () => {
  const input = {
    fingerprint: "0".repeat(64),
    ruleId: "sca-ghsa-x84v-xcm2-53pg",
    file: "requirements.txt",
    advisoryId: "GHSA-x84v-xcm2-53pg",
    aliases: ["PYSEC-2018-28", "CVE-2018-18074"],
    packageName: "requests",
  };

  it("accepts a rule id derived from any alias of the advisory", () => {
    for (const rule of ["sca-pysec-2018-28", "sca-cve-2018-18074", "sca-ghsa-x84v-xcm2-53pg"]) {
      expect(matchIgnoreEntry([{ rule, reason: "accepted" }], input, "2026-01-01"), rule).toEqual({
        source: "ignore-file",
        entry: 0,
        reason: "accepted",
      });
    }
  });

  it("still honours paths and does not widen non-SCA rules", () => {
    expect(
      matchIgnoreEntry(
        [{ rule: "sca-pysec-2018-28", paths: ["other/**"], reason: "r" }],
        input,
        "2026-01-01",
      ),
    ).toBeUndefined();
    expect(
      matchIgnoreEntry([{ rule: "sca-pysec-2019-1", reason: "r" }], input, "2026-01-01"),
    ).toBeUndefined();
    expect(
      matchIgnoreEntry(
        [{ rule: "sca-pysec-2018-28", reason: "r" }],
        { ...input, ruleId: "py-eval-dynamic" },
        "2026-01-01",
      ),
    ).toBeUndefined();
  });
});

import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import {
  HttpError,
  compareSemver,
  extractFixedVersion,
  manifestLockfileIssues,
  parseCargoLock,
  parseCargoManifestDependencies,
  parseLockfile,
  groupAdvisories,
  normalizePackageName,
  parseCvssV3,
  parseGoMod,
  parsePackageLock,
  parsePackagesLock,
  parsePipfileDependencies,
  parsePipfileLock,
  parsePdmLock,
  parsePnpmLock,
  parsePoetryLock,
  parsePomXml,
  parsePylock,
  parsePyprojectDependencies,
  parseRequirements,
  parseUvLock,
  pickAdvisoryId,
  runSca,
  type HttpClient,
} from "../src/sca.js";
import { comparePypiVersions } from "../src/pypi.js";
import { recommendUpgrade } from "../src/report.js";
import { parseTomlSubset } from "../src/toml.js";
import { FIXTURES, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("sca");

afterAll(() => cleanup(temp));

describe("lockfile parsers", () => {
  it("parses package-lock.json v3", () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.15" },
        "node_modules/@scope/pkg": { version: "1.2.3" },
      },
    });
    const parsed = parsePackageLock(content, "package-lock.json");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "lodash@4.17.15",
      "@scope/pkg@1.2.3",
    ]);
  });

  it("parses pnpm-lock.yaml (v9 keys and scoped packages)", () => {
    const content = [
      "lockfileVersion: '9.0'",
      "packages:",
      "  lodash@4.17.15:",
      "    resolution: {integrity: sha512-fake}",
      "  '@scope/pkg@1.2.3':",
      "    resolution: {integrity: sha512-fake}",
      "",
    ].join("\n");
    const parsed = parsePnpmLock(content, "pnpm-lock.yaml");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "lodash@4.17.15",
      "@scope/pkg@1.2.3",
    ]);
  });

  it("parses only == pinned requirements", () => {
    const content = "Django==3.2.0\nrequests>=2.0\nflask==2.2.5 # pinned\n";
    const parsed = parseRequirements(content, "requirements.txt");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "Django@3.2.0",
      "flask@2.2.5",
    ]);
    expect(parsed.warnings[0]).toContain("unresolved transitive dependencies");
  });

  it("parses poetry.lock blocks", () => {
    const content = [
      "[[package]]",
      'name = "django"',
      'version = "3.2.0"',
      "",
      "[[package]]",
      'name = "requests"',
      'version = "2.19.0"',
      "",
    ].join("\n");
    const parsed = parsePoetryLock(content, "poetry.lock");
    expect(parsed.packages).toHaveLength(2);
    expect(parsed.packages[0]).toMatchObject({
      name: "django",
      version: "3.2.0",
      ecosystem: "PyPI",
    });
  });

  it("parses go.mod require blocks", () => {
    const content = [
      "module example.com/app",
      "",
      "require (",
      "\tgithub.com/gin-gonic/gin v1.7.0",
      "\tgolang.org/x/text v0.3.5 // indirect",
      ")",
      "",
      "require github.com/pkg/errors v0.9.1",
      "",
    ].join("\n");
    const parsed = parseGoMod(content, "go.mod");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "github.com/gin-gonic/gin@v1.7.0",
      "golang.org/x/text@v0.3.5",
      "github.com/pkg/errors@v0.9.1",
    ]);
    expect(parsed.packages[1]?.direct).toBe(false);
  });

  it("parses literal-version direct Maven dependencies only", () => {
    const content = [
      "<project>",
      "  <dependencyManagement><dependencies>",
      "    <dependency><groupId>managed</groupId><artifactId>lib</artifactId><version>9.9.9</version></dependency>",
      "  </dependencies></dependencyManagement>",
      "  <dependencies>",
      "    <dependency><groupId>org.example</groupId><artifactId>app</artifactId><version>1.2.3</version></dependency>",
      "    <dependency><groupId>org.example</groupId><artifactId>prop</artifactId><version>${prop.version}</version></dependency>",
      "  </dependencies>",
      "</project>",
      "",
    ].join("\n");
    const parsed = parsePomXml(content, "pom.xml");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "org.example:app@1.2.3",
    ]);
    expect(parsed.warnings[0]).toContain("unresolved transitive dependencies");
  });

  it("parses packages.lock.json for NuGet", () => {
    const content = JSON.stringify({
      version: 1,
      dependencies: {
        "net8.0": {
          "Newtonsoft.Json": {
            type: "Direct",
            resolved: "12.0.1",
          },
        },
      },
    });
    const parsed = parsePackagesLock(content, "packages.lock.json");
    expect(parsed.packages[0]).toMatchObject({
      name: "Newtonsoft.Json",
      version: "12.0.1",
      ecosystem: "NuGet",
    });
  });

  it("computes CVSS v3 base scores", () => {
    expect(
      parseCvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ).toBeCloseTo(9.8, 1);
    expect(
      parseCvssV3("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"),
    ).toBeLessThan(4);
  });
});

function makeProject(): { root: string; packages: string } {
  const root = path.join(temp, "project");
  const packages = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "app", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.15" },
      "node_modules/minimist": { version: "1.2.5" },
    },
  });
  writeFile(root, "package-lock.json", packages);
  return { root, packages };
}

function makeMockClient(counters: { post: number; get: number }): HttpClient {
  return {
    async postJson(_url, body) {
      counters.post += 1;
      const queries = (body as { queries: unknown[] }).queries;
      return {
        results: queries.map(() => ({ vulns: [{ id: "GHSA-test-0001" }] })),
      };
    },
    async getJson(url) {
      counters.get += 1;
      expect(url).toContain("GHSA-test-0001");
      return {
        id: "GHSA-test-0001",
        summary: "Prototype pollution in test package",
        aliases: ["CVE-2020-0001"],
        severity: [
          {
            type: "CVSS_V3",
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          },
        ],
        affected: [
          {
            ranges: [{ events: [{ fixed: "4.17.19" }] }],
          },
        ],
        database_specific: { cwe_ids: ["CWE-1321"] },
      };
    },
  };
}

describe("OSV SCA orchestration", () => {
  it("batches queries, fetches details and builds findings", async () => {
    const { root } = makeProject();
    const counters = { post: 0, get: 0 };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: makeMockClient(counters),
      batchSize: 1,
    });

    expect(result.packages).toHaveLength(2);
    expect(counters.post).toBe(2);
    expect(counters.get).toBe(1);
    expect(result.findings).toHaveLength(2);
    for (const finding of result.findings) {
      expect(finding.category).toBe("sca");
      expect(finding.severity).toBe("critical");
      expect(finding.cvss).toBeCloseTo(9.8, 1);
      expect(finding.fixedVersion).toBe("4.17.19");
      expect(finding.advisoryId).toBe("GHSA-test-0001");
      expect(finding.aliases).toContain("CVE-2020-0001");
      expect(finding.reachable).toBe("unknown");
    }
  });

  it("degrades to a warning when the OSV query fails", async () => {
    const { root } = makeProject();
    const client: HttpClient = {
      async postJson() {
        throw new Error("network down");
      },
      async getJson() {
        throw new Error("should not be called");
      },
    };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: client,
    });
    expect(result.findings).toHaveLength(0);
    expect(result.warnings.join("\n")).toContain("OSV batch query failed");
    expect(result.degraded).toBe(true);
  });

  it("keeps status ok when inputs are unresolved but queries succeed", async () => {
    const root = path.join(temp, "unresolved-ok");
    writeFile(
      root,
      "package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app", version: "1.0.0" },
          "node_modules/lodash": { version: "4.17.15" },
        },
      }),
    );
    writeFile(root, "requirements.txt", "Django==3.2.0\nrequests>=2.0\n");
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: makeMockClient({ post: 0, get: 0 }),
    });
    expect(result.warnings.join("\n")).toContain("unresolved transitive dependencies");
    expect(result.unresolvedManifests.length).toBeGreaterThan(0);
    expect(result.degraded).toBe(false);
  });

  it("normalizes PyPI names in OSV query payloads", async () => {
    const root = path.join(temp, "pypi-normalize");
    writeFile(root, "requirements.txt", "Django==3.2.0\nFlask_Login==0.6.1\n");
    const sent: string[] = [];
    const client: HttpClient = {
      async postJson(_url, body) {
        for (const query of (body as { queries: Array<{ package: { name: string } }> })
          .queries) {
          sent.push(query.package.name);
        }
        return { results: (body as { queries: unknown[] }).queries.map(() => ({})) };
      },
      async getJson() {
        throw new Error("should not be called");
      },
    };
    await runSca({ root, inventory: inventory(root), http: client });
    expect(sent.sort()).toEqual(["django", "flask-login"]);
  });

  it("skips network access entirely in offline mode", async () => {
    const { root } = makeProject();
    const counters = { post: 0, get: 0 };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: makeMockClient(counters),
      offline: true,
    });
    expect(counters).toEqual({ post: 0, get: 0 });
    expect(result.packages).toHaveLength(2);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings.join("\n")).toContain("offline mode");
  });
});

describe("fixed version selection", () => {
  it("picks the smallest fixed version above the installed version", () => {
    const detail = {
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ events: [{ fixed: "4.17.21" }] }],
        },
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [
            { events: [{ last_affected: "4.17.18" }] },
            { events: [{ fixed: "4.17.20" }] },
            { events: [{ fixed: "4.17.19" }] },
          ],
        },
        {
          package: { name: "other", ecosystem: "npm" },
          ranges: [{ events: [{ fixed: "1.0.0" }] }],
        },
      ],
    };
    expect(
      extractFixedVersion(detail, {
        name: "lodash",
        version: "4.17.15",
        ecosystem: "npm",
      }),
    ).toBe("4.17.19");
  });

  it("returns undefined when the advisory only has last_affected", () => {
    const detail = {
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ events: [{ last_affected: "4.17.15" }] }],
        },
      ],
    };
    expect(
      extractFixedVersion(detail, {
        name: "lodash",
        version: "4.17.15",
        ecosystem: "npm",
      }),
    ).toBeUndefined();
  });

  it("ignores fixed versions that do not upgrade the installed version", () => {
    const detail = {
      affected: [{ ranges: [{ events: [{ fixed: "4.17.15" }] }] }],
    };
    expect(
      extractFixedVersion(detail, { name: "lodash", version: "4.17.15" }),
    ).toBeUndefined();
  });

  it("normalizes package names per ecosystem", () => {
    expect(normalizePackageName("Django", "PyPI")).toBe("django");
    expect(normalizePackageName("Flask_Login", "PyPI")).toBe("flask-login");
    expect(normalizePackageName("zope.interface", "PyPI")).toBe("zope-interface");
    expect(normalizePackageName("My-Pkg", "npm")).toBe("My-Pkg");
    expect(normalizePackageName("github.com/Foo/Bar", "Go")).toBe(
      "github.com/Foo/Bar",
    );
    expect(normalizePackageName("Newtonsoft.Json", "NuGet")).toBe(
      "newtonsoft.json",
    );
  });

  it("matches PyPI advisories case- and separator-insensitively", () => {
    const detail = {
      affected: [
        {
          package: { name: "django", ecosystem: "PyPI" },
          ranges: [{ events: [{ fixed: "3.2.25" }] }],
        },
        {
          package: { name: "flask-login", ecosystem: "PyPI" },
          ranges: [{ events: [{ fixed: "0.6.3" }] }],
        },
      ],
    };
    expect(
      extractFixedVersion(detail, {
        name: "Django",
        version: "3.2.0",
        ecosystem: "PyPI",
      }),
    ).toBe("3.2.25");
    expect(
      extractFixedVersion(detail, {
        name: "Flask_Login",
        version: "0.6.1",
        ecosystem: "PyPI",
      }),
    ).toBe("0.6.3");
  });
});

function makeWideProject(count: number): string {
  const root = path.join(temp, `wide-${count}`);
  const packages: Record<string, unknown> = {
    "": { name: "app", version: "1.0.0" },
  };
  for (let index = 0; index < count; index += 1) {
    packages[`node_modules/pkg-${index}`] = { version: "1.0.0" };
  }
  writeFile(
    root,
    "package-lock.json",
    JSON.stringify({ lockfileVersion: 3, packages }),
  );
  return root;
}

describe("OSV robustness", () => {
  it("fetches each advisory detail once and reuses it across packages", async () => {
    const { root } = makeProject();
    const counters = { post: 0, get: 0 };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: makeMockClient(counters),
    });
    expect(result.findings).toHaveLength(2);
    expect(result.vulnIds).toEqual(["GHSA-test-0001"]);
    expect(counters.get).toBe(1);
  });

  it("limits concurrent detail fetches to the configured concurrency", async () => {
    const root = makeWideProject(20);
    let getCount = 0;
    let inFlight = 0;
    let maxInFlight = 0;
    const client: HttpClient = {
      async postJson(_url, body) {
        const queries = (body as { queries: unknown[] }).queries;
        return {
          results: queries.map((_query, index) => ({
            vulns: [{ id: `GHSA-conc-${index}` }],
          })),
        };
      },
      async getJson() {
        getCount += 1;
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((resolve) => setTimeout(resolve, 5));
        inFlight -= 1;
        return { affected: [] };
      },
    };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: client,
      detailConcurrency: 8,
    });
    expect(getCount).toBe(20);
    expect(result.vulnIds).toHaveLength(20);
    expect(maxInFlight).toBeLessThanOrEqual(8);
    expect(maxInFlight).toBeGreaterThan(1);
  });

  it("retries 429/5xx responses with exponential backoff", async () => {
    const { root } = makeProject();
    let postAttempts = 0;
    let getAttempts = 0;
    const delays: number[] = [];
    const client: HttpClient = {
      async postJson(_url, body) {
        postAttempts += 1;
        if (postAttempts < 3) throw new HttpError(429, "Too Many Requests");
        const queries = (body as { queries: unknown[] }).queries;
        return {
          results: queries.map(() => ({
            vulns: [{ id: "GHSA-retry-0001" }],
          })),
        };
      },
      async getJson() {
        getAttempts += 1;
        if (getAttempts === 1) throw new HttpError(503, "Service Unavailable");
        return {
          id: "GHSA-retry-0001",
          database_specific: { severity: "HIGH" },
          affected: [{ ranges: [{ events: [{ fixed: "9.0.0" }] }] }],
        };
      },
    };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: client,
      maxRetries: 3,
      retryBaseMs: 10,
      sleep: async (ms) => {
        delays.push(ms);
      },
    });
    expect(postAttempts).toBe(3);
    expect(getAttempts).toBe(2);
    expect(delays).toEqual([10, 20, 10]);
    expect(result.findings).toHaveLength(2);
    expect(result.warnings.join("\n")).not.toContain("OSV batch query failed");
    expect(result.warnings.join("\n")).not.toContain(
      "OSV vulnerability detail fetch failed",
    );
  });

  it("does not retry non-retryable HTTP errors", async () => {
    const { root } = makeProject();
    let attempts = 0;
    const client: HttpClient = {
      async postJson() {
        attempts += 1;
        throw new HttpError(400, "Bad Request");
      },
      async getJson() {
        throw new Error("should not be called");
      },
    };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: client,
      maxRetries: 3,
    });
    expect(attempts).toBe(1);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings.join("\n")).toContain("OSV batch query failed");
  });
});

describe("fixture lockfiles", () => {
  it("finds the seeded vulnerable packages in fixtures", () => {
    const lock = fs.readFileSync(
      path.join(FIXTURES, "vulnerable/sca/package-lock.json"),
      "utf8",
    );
    const packages = parsePackageLock(lock, "package-lock.json");
    expect(packages.packages.map((pkg) => pkg.name)).toEqual(
      expect.arrayContaining(["lodash", "minimist"]),
    );
  });
});

describe("Python dependency files", () => {
  it("parses uv.lock and skips the project's own virtual package", () => {
    const content = [
      "version = 1",
      "[[package]]",
      'name = "myapp"',
      'version = "0.1.0"',
      'source = { virtual = "." }',
      "[[package]]",
      'name = "jinja2"',
      'version = "2.10"',
      'source = { registry = "https://pypi.org/simple" }',
      "[[package]]",
      'name = "markupsafe"',
      'version = "1.1.1"',
      'source = { editable = "." }',
      "",
    ].join("\n");
    const parsed = parseUvLock(content, "uv.lock", new Set(["jinja2"]));
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "jinja2@2.10",
    ]);
    expect(parsed.packages[0]?.direct).toBe(true);
    expect(parsed.packages[0]?.line).toBe(6);
  });

  it("marks only pyproject-declared packages as direct in pdm.lock", () => {
    const content = [
      "[[package]]",
      'name = "pyyaml"',
      'version = "5.3"',
      "[[package]]",
      'name = "urllib3"',
      'version = "1.24.1"',
      "",
    ].join("\n");
    const parsed = parsePdmLock(content, "pdm.lock", new Set(["pyyaml"]));
    expect(parsed.packages.map((pkg) => pkg.direct)).toEqual([true, false]);
  });

  it("keeps every package direct and warns when no pyproject.toml is present", () => {
    const parsed = parsePoetryLock(
      '[[package]]\nname = "django"\nversion = "3.2.0"\n',
      "poetry.lock",
    );
    expect(parsed.packages[0]?.direct).toBe(true);
    expect(parsed.warnings.join("\n")).toContain("no pyproject.toml");
  });

  it("parses Pipfile.lock and marks develop entries as dev", () => {
    const content = JSON.stringify({
      default: { requests: { version: "==2.19.0" } },
      develop: { pytest: { version: "==5.0.0" } },
    });
    const parsed = parsePipfileLock(content, "Pipfile.lock");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "requests@2.19.0",
      "pytest@5.0.0",
    ]);
    expect(parsed.packages.find((pkg) => pkg.name === "pytest")?.dev).toBe(true);
    expect(parsed.packages.find((pkg) => pkg.name === "requests")?.dev).toBe(false);
  });

  it("parses PEP 751 pylock.toml packages", () => {
    const content = [
      'lock-version = "1.0"',
      "[[packages]]",
      'name = "urllib3"',
      'version = "1.24.1"',
      "[[packages]]",
      'name = "requests"',
      'version = "2.19.0"',
      "",
    ].join("\n");
    const parsed = parsePylock(content, "pylock.toml");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "urllib3@1.24.1",
      "requests@2.19.0",
    ]);
    expect(parsed.packages[0]?.line).toBe(2);
  });

  it("extracts direct dependency names from every pyproject.toml layout", () => {
    const content = [
      "[project]",
      'name = "app"',
      'dependencies = ["requests>=2.0", "flask[async]==3.0.0"]',
      "[project.optional-dependencies]",
      'docs = ["mkdocs>=1.0"]',
      "[tool.poetry.dependencies]",
      'python = "^3.9"',
      'django = "^4.2"',
      "[tool.poetry.group.dev.dependencies]",
      'pytest = "^8.0"',
      "[dependency-groups]",
      'test = ["coverage>=7.0"]',
      "",
    ].join("\n");
    const { names, warning } = parsePyprojectDependencies(content, "pyproject.toml");
    expect(warning).toBeUndefined();
    expect([...names].sort()).toEqual(
      ["coverage", "django", "flask", "mkdocs", "pytest", "requests"].sort(),
    );
  });

  it("resolves requirements includes, continuations, markers and URL entries", () => {
    const root = path.join(temp, "req-project");
    writeFile(root, "requirements/requirements.txt", [
      "-r base.txt",
      "-c ../constraints.txt",
      "--hash=sha256:deadbeef",
      "Django==3.2.0 \\",
      "    --hash=sha256:cafebabe",
      'requests==2.19.0 ; python_version < "3.9"',
      "flask[async]==2.0.0",
      "uvicorn===0.11.0",
      "git+https://github.com/example/repo.git",
      "mypkg @ https://example.invalid/pkg.whl",
      "",
    ].join("\n"));
    writeFile(root, "requirements/base.txt", "jinja2==2.10\n");
    writeFile(root, "constraints.txt", "django==3.2.0\n");
    const content = fs.readFileSync(
      path.join(root, "requirements/requirements.txt"),
      "utf8",
    );
    const parsed = parseRequirements(content, "requirements/requirements.txt", {
      root,
      visited: new Set<string>(),
    });
    const names = parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`);
    expect(names).toEqual(
      expect.arrayContaining([
        "jinja2@2.10",
        "Django@3.2.0",
        "requests@2.19.0",
        "flask@2.0.0",
        "uvicorn@0.11.0",
      ]),
    );
    expect(names).not.toContain("django@3.2.0");
    expect(parsed.warnings.join("\n")).toContain(
      "2 direct URL/VCS entries cannot be checked",
    );
  });

  it("does not double-count a requirements include", () => {
    const root = path.join(temp, "req-cycle");
    writeFile(root, "requirements/a.txt", "-r b.txt\nflask==2.0.0\n");
    writeFile(root, "requirements/b.txt", "-r a.txt\ndjango==3.2.0\n");
    const parsed = parseRequirements(
      fs.readFileSync(path.join(root, "requirements/a.txt"), "utf8"),
      "requirements/a.txt",
      { root, visited: new Set<string>() },
    );
    expect(parsed.packages.map((pkg) => pkg.name).sort()).toEqual([
      "django",
      "flask",
    ]);
  });

  it("reads the small TOML subset used by the lockfiles", () => {
    const content = [
      'title = "demo"',
      "[tool.poetry.dependencies]",
      'python = "^3.9"',
      "packages = [",
      '  "requests>=2.0",',
      '  "flask",',
      "]",
      "[[package]]",
      'name = "requests"',
      'source = { registry = "https://pypi.org/simple" }',
      "",
    ].join("\n");
    const { data, error } = parseTomlSubset(content, "demo.toml");
    expect(error).toBeUndefined();
    expect(data.title).toBe("demo");
    const tool = data.tool as Record<string, unknown>;
    const poetry = tool.poetry as Record<string, unknown>;
    const deps = poetry.dependencies as Record<string, unknown>;
    expect(deps.python).toBe("^3.9");
    const packages = data.package as Array<Record<string, unknown>>;
    expect(packages[0]?.name).toBe("requests");
    const source = packages[0]?.source as Record<string, unknown>;
    expect(source.registry).toBe("https://pypi.org/simple");
  });
});

describe("PEP 440 comparison", () => {
  const ordered: Array<[string, string]> = [
    ["1.0.dev1", "1.0a1"],
    ["1.0a1", "1.0b1"],
    ["1.0b1", "1.0rc1"],
    ["1.0rc1", "1.0"],
    ["1.0", "1.0.post1"],
    ["1.0.post1.dev1", "1.0.post1"],
    ["1.0", "1.0.1"],
    ["1.0.1", "1.0.2"],
    ["1.9.9", "2.0"],
    ["1.0a1", "1.0"],
    ["0.9", "1.0"],
    ["1.0b1", "1.0b2"],
    ["1.0a1", "1.0a2"],
    ["1.0", "1.0+local"],
    ["1.0+abc", "1.0+abd"],
    ["1.0.0", "1.0.0.1"],
    ["1!1.0", "2!0.1"],
    ["1.0", "1!0.1"],
    ["1.0rc1", "1.0.1"],
    ["1.0.dev1", "1.0"],
    ["2.0.0", "2.0.1"],
    ["1.0.0", "1.0.1"],
  ];

  it("orders at least 20 pairs correctly", () => {
    expect(ordered.length).toBeGreaterThanOrEqual(20);
    for (const [lower, higher] of ordered) {
      expect(comparePypiVersions(lower, higher)).toBeLessThan(0);
      expect(comparePypiVersions(higher, lower)).toBeGreaterThan(0);
    }
  });

  it("treats trailing zeros and a v prefix as equal", () => {
    expect(comparePypiVersions("1.0", "1.0.0")).toBe(0);
    expect(comparePypiVersions("v1.0", "1.0.0")).toBe(0);
    expect(comparePypiVersions("1.0.0.0", "1.0")).toBe(0);
  });

  it("uses PEP 440 ordering for PyPI fixed versions", () => {
    const detail = { affected: [{ ranges: [{ events: [{ fixed: "1.0.0" }] }] }] };
    expect(
      extractFixedVersion(detail, { name: "demo", version: "1.0", ecosystem: "PyPI" }),
    ).toBeUndefined();
    const post = { affected: [{ ranges: [{ events: [{ fixed: "1.0.post1" }] }] }] };
    expect(
      extractFixedVersion(post, { name: "demo", version: "1.0", ecosystem: "PyPI" }),
    ).toBe("1.0.post1");
  });
});

describe("Python lockfile fixtures", () => {
  it("marks transitive packages in the uv fixture as not direct", async () => {
    const root = path.join(FIXTURES, "vulnerable/sca/python/uv");
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    const jinja = result.packages.find((pkg) => pkg.name === "jinja2");
    const markupsafe = result.packages.find((pkg) => pkg.name === "markupsafe");
    expect(jinja?.direct).toBe(true);
    expect(markupsafe?.direct).toBe(false);
    expect(result.packages.some((pkg) => pkg.name === "myapp")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Regression tests from the adversarial review of the Python dependency code.
// Lockfile samples below are hand-built in the shape the real tools write.
// ---------------------------------------------------------------------------

/** Run `fn` and fail when it takes longer than `limitMs` (regex backtracking guard). */
function within<T>(limitMs: number, fn: () => T): T {
  const started = Date.now();
  const result = fn();
  expect(Date.now() - started).toBeLessThan(limitMs);
  return result;
}

describe("TOML reader hardening", () => {
  it("never writes through __proto__ or constructor keys", () => {
    const { data, error } = parseTomlSubset(
      [
        "[__proto__]",
        'polluted = "yes"',
        "[constructor.prototype]",
        "polluted2 = 1",
        "[tool.poetry.dependencies]",
        'constructor = "^1.0"',
        '__proto__ = { polluted3 = 1 }',
        "",
      ].join("\n"),
      "evil.toml",
    );
    expect(error).toBeUndefined();
    const probe = {} as Record<string, unknown>;
    expect(probe.polluted).toBeUndefined();
    expect(probe.polluted2).toBeUndefined();
    expect(probe.polluted3).toBeUndefined();
    // The keys are still readable as ordinary data.
    expect(Object.keys(data)).toEqual(
      expect.arrayContaining(["__proto__", "constructor", "tool"]),
    );
    const parsed = parsePyprojectDependencies(
      '[tool.poetry.dependencies]\nconstructor = "^1.0"\ntoString = "*"\n',
      "pyproject.toml",
    );
    expect([...parsed.names].sort()).toEqual(["constructor", "tostring"]);
  });

  it("reads escapes, multi-line strings, comments, CRLF, BOM and multi-line inline tables", () => {
    const content = [
      "\uFEFF# leading comment",
      'a = "quote \\" hash # not a comment \\u00e9 \\U0001F600" # trailing comment',
      "b = 'C:\\literal\\path # still string'",
      'c = """',
      "first line",
      'has "quotes" and \\',
      '   a continuation"""',
      "d = [ 1, # one",
      '  "two", { x = 1, y = [2, 3] },',
      "]",
      "e = { name = \"x\",",
      "  marker = \"python_version < '3.9'\", }",
      "f = 2024-07-26 18:15:03Z",
      "[[package]] # header comment",
      'name = "p"',
      "",
    ].join("\r\n");
    const { data, error, lineOf } = parseTomlSubset(content, "t.toml");
    expect(error).toBeUndefined();
    expect(data.a).toBe('quote " hash # not a comment \u00e9 \u{1F600}');
    expect(data.b).toBe("C:\\literal\\path # still string");
    expect(data.c).toBe('first line\r\nhas "quotes" and a continuation');
    expect(data.d).toEqual([1, "two", { x: 1, y: [2, 3] }]);
    expect(data.e).toEqual({ name: "x", marker: "python_version < '3.9'" });
    expect(data.f).toBe("2024-07-26 18:15:03Z");
    const packages = data.package as Array<Record<string, never>>;
    expect(packages).toHaveLength(1);
    expect(lineOf(packages[0] as never)).toBe(14);
  });

  it("returns a warning instead of throwing or hanging on malformed input", () => {
    const cases = [
      'name = "unterminated\nversion = "1"\n',
      "x = " + "[".repeat(200_000),
      "x = " + "{a=".repeat(200_000),
      "[[package]\nname = 1\n",
      "= 1\n",
      'a = """never closed',
      "a = 1 2 3\n",
      "[a]\nb = 1\n[a.b]\nc = 1\n",
      "\u0000\u0001\u0002",
      "a = " + " ".repeat(300_000) + "\n",
    ];
    for (const input of cases) {
      const result = within(2_000, () => parseTomlSubset(input, "bad.toml"));
      expect(result.error).toContain("bad.toml: TOML parse failed");
      expect(result.data).toEqual({});
    }
  });
});

describe("uv.lock (real shape)", () => {
  const uvLock = [
    "version = 1",
    "revision = 2",
    'requires-python = ">=3.10"',
    "resolution-markers = [",
    "    \"python_full_version >= '3.12'\",",
    "    \"python_full_version < '3.12'\",",
    "]",
    "",
    "[[package]]",
    'name = "anyio"',
    'version = "4.14.2"',
    'source = { registry = "https://pypi.org/simple" }',
    "dependencies = [",
    '    { name = "idna" },',
    "    { name = \"typing-extensions\", marker = \"python_full_version < '3.13'\" },",
    "]",
    'sdist = { url = "https://files.pythonhosted.org/packages/aa/anyio-4.14.2.tar.gz", hash = "sha256:c0", size = 24210, upload-time = "2024-07-26T18:15:03.762Z" }',
    "wheels = [",
    '    { url = "https://files.pythonhosted.org/packages/bb/anyio-4.14.2-py3-none-any.whl", hash = "sha256:fc", size = 13929 },',
    "]",
    "",
    "[[package]]",
    'name = "asgiref"',
    'version = "3.12.1"',
    'source = { registry = "https://pypi.org/simple" }',
    "",
    "[[package]]",
    'name = "demo-app"',
    'version = "3.2.0.dev0"',
    'source = { editable = "." }',
    "dependencies = [",
    '    { name = "Jinja2" },',
    '    { name = "httpx", extra = ["http2"] },',
    "]",
    "",
    "[package.optional-dependencies]",
    "async = [",
    '    { name = "asgiref" },',
    "]",
    "",
    "[package.dev-dependencies]",
    "dev = [",
    '    { name = "pytest" },',
    '    { name = "asgiref" },',
    "]",
    "",
    "[package.metadata]",
    "requires-dist = [",
    "    { name = \"asgiref\", marker = \"extra == 'async'\", specifier = \">=3.2\" },",
    '    { name = "jinja2", specifier = ">=3.1.2" },',
    "]",
    'provides-extras = ["async"]',
    "",
    "[[package]]",
    'name = "h2"',
    'version = "4.1.0"',
    'source = { registry = "https://pypi.org/simple" }',
    "",
    "[[package]]",
    'name = "httpx"',
    'version = "0.27.0"',
    'source = { registry = "https://pypi.org/simple" }',
    "dependencies = [",
    '    { name = "anyio" },',
    "]",
    "",
    "[package.optional-dependencies]",
    "http2 = [",
    '    { name = "h2" },',
    "]",
    "socks = [",
    '    { name = "socksio" },',
    "]",
    "",
    "[[package]]",
    'name = "idna"',
    'version = "3.4"',
    'source = { registry = "https://pypi.org/simple" }',
    "",
    "[[package]]",
    'name = "jinja2"',
    'version = "2.10"',
    'source = { registry = "https://pypi.org/simple" }',
    "dependencies = [",
    '    { name = "markupsafe" },',
    "]",
    "",
    "[[package]]",
    'name = "markupsafe"',
    'version = "1.1.1"',
    'source = { registry = "https://pypi.org/simple" }',
    "",
    "[[package]]",
    'name = "pytest"',
    'version = "8.0.0"',
    'source = { registry = "https://pypi.org/simple" }',
    "dependencies = [",
    '    { name = "idna" },',
    '    { name = "pluggy" },',
    "]",
    "",
    "[[package]]",
    'name = "pluggy"',
    'version = "1.5.0"',
    'source = { registry = "https://pypi.org/simple" }',
    "",
    "[[package]]",
    'name = "socksio"',
    'version = "1.0.0"',
    'source = { registry = "https://pypi.org/simple" }',
    "",
    "[[package]]",
    'name = "typing-extensions"',
    'version = "4.12.0"',
    'source = { registry = "https://pypi.org/simple" }',
    "",
    "[[package]]",
    'name = "workspace-member"',
    'version = "0.1.0"',
    'source = { editable = "packages/member" }',
    "dependencies = [",
    '    { name = "pluggy" },',
    "]",
    "",
    "[[package]]",
    'name = "vendored"',
    'source = { git = "https://example.invalid/vendored.git?rev=abc#abc" }',
    "",
  ].join("\n");

  it("derives direct and scope from the lockfile itself, without a pyproject.toml", () => {
    const parsed = parseUvLock(uvLock, "uv.lock");
    const by = new Map(parsed.packages.map((pkg) => [pkg.name, pkg]));
    // Independent count: [[package]] blocks minus the project, the workspace
    // member and the git entry without a version.
    const blocks = uvLock.split("\n").filter((line) => line === "[[package]]").length;
    expect(blocks).toBe(14);
    expect(parsed.packages).toHaveLength(blocks - 3);
    expect(by.has("demo-app")).toBe(false);
    expect(by.has("workspace-member")).toBe(false);

    expect(by.get("jinja2")).toMatchObject({ direct: true, scope: "runtime", version: "2.10" });
    expect(by.get("markupsafe")).toMatchObject({ direct: false, scope: "runtime" });
    expect(by.get("httpx")).toMatchObject({ direct: true, scope: "runtime" });
    // Reached through the requested `http2` extra of httpx, but not `socks`.
    expect(by.get("h2")).toMatchObject({ direct: false, scope: "runtime" });
    expect(by.get("socksio")).toMatchObject({ direct: false, scope: "unknown" });
    // idna is reachable from both runtime (httpx -> anyio) and dev (pytest).
    expect(by.get("idna")).toMatchObject({ direct: false, scope: "runtime" });
    // asgiref is an extra and a dev-group member: the stronger scope wins.
    expect(by.get("asgiref")).toMatchObject({ direct: true, scope: "optional" });
    expect(by.get("pytest")).toMatchObject({ direct: true, scope: "dev", dev: true });
    // pluggy is needed by pytest (dev) and by the workspace member (runtime).
    expect(by.get("pluggy")).toMatchObject({ direct: true, scope: "runtime" });

    const lines = uvLock.split("\n");
    for (const pkg of parsed.packages) {
      expect(lines[pkg.line - 1]).toBe("[[package]]");
      expect(lines[pkg.line]).toBe(`name = "${pkg.name}"`);
    }
    expect(parsed.warnings.join("\n")).toContain("1 entries without a version");
    expect(parsed.warnings.join("\n")).not.toContain("no pyproject.toml");
  });

  it("gives the same result for CRLF line endings and a byte order mark", () => {
    const plain = parseUvLock(uvLock, "uv.lock");
    const crlf = parseUvLock(`\uFEFF${uvLock.replace(/\n/g, "\r\n")}`, "uv.lock");
    expect(crlf.packages).toEqual(plain.packages);
  });

  it("falls back to a line scan with a warning when the TOML is malformed", () => {
    const broken = uvLock.replace(
      'name = "idna"',
      'name = "idna"\nbroken = [ { unterminated = "x }',
    );
    const parsed = within(2_000, () => parseUvLock(broken, "uv.lock"));
    expect(parsed.warnings.join("\n")).toContain("TOML parse failed");
    expect(parsed.warnings.join("\n")).toContain("line-based fallback");
    const names = parsed.packages.map((pkg) => pkg.name);
    expect(names).toEqual(expect.arrayContaining(["jinja2", "idna", "pytest"]));
    expect(names).not.toContain("demo-app");
    expect(names).not.toContain("workspace-member");
    expect(parsed.packages.every((pkg) => pkg.scope === "unknown")).toBe(true);
  });

  it("stays fast on very large and pathological lockfiles", () => {
    let big = "";
    for (let i = 0; i < 50_000; i += 1) {
      big += `[[package]]\nname = "p${i}"\nversion = "1.${i}"\ndependencies = [{ name = "p${i + 1}" }]\n`;
    }
    const parsed = within(5_000, () => parseUvLock(big, "uv.lock", new Set(["p0"])));
    expect(parsed.packages).toHaveLength(50_000);
    expect(parsed.packages.at(-1)?.line).toBe(4 * 49_999 + 1);
    const hostile = `[[package]]\nname = ${" ".repeat(400_000)}\n${'name = "'.repeat(50_000)}`;
    const result = within(5_000, () => parseUvLock(hostile, "uv.lock"));
    expect(result.packages).toEqual([]);
    expect(result.warnings.join("\n")).toContain("TOML parse failed");
  });
});

describe("poetry.lock, pdm.lock and pylock.toml (real shapes)", () => {
  it("reads dev scope from poetry 1.x `category` and skips directory sources", () => {
    const lock = [
      "# This file is automatically @generated by Poetry and should not be changed by hand.",
      "",
      "[[package]]",
      'name = "Django"',
      'version = "3.2.0"',
      'description = "A high-level Python Web framework with \\"batteries\\" # included."',
      'category = "main"',
      "optional = false",
      'python-versions = ">=3.6"',
      "files = [",
      '    {file = "Django-3.2-py3-none-any.whl", hash = "sha256:0604e84c4fb698a5e53e5857b5aea945b2f19a18f25f10b8748dbdf935788927"},',
      '    {file = "Django-3.2.tar.gz", hash = "sha256:21f55822cc2d2b5cb6a1d2e3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3"},',
      "]",
      "",
      "[package.dependencies]",
      'asgiref = ">=3.3.2,<4"',
      'sqlparse = {version = ">=0.2.2", markers = "python_version >= \\"3.6\\""}',
      "",
      "[package.extras]",
      'argon2 = ["argon2-cffi (>=19.1.0)"]',
      "",
      "[[package]]",
      'name = "asgiref"',
      'version = "3.6.0"',
      'category = "main"',
      "optional = false",
      "",
      "[[package]]",
      'name = "pytest"',
      'version = "7.0.0"',
      'category = "dev"',
      "optional = false",
      "",
      "[[package]]",
      'name = "argon2-cffi"',
      'version = "21.3.0"',
      'category = "main"',
      "optional = true",
      "",
      "[[package]]",
      'name = "local-lib"',
      'version = "0.1.0"',
      'category = "main"',
      "optional = false",
      "",
      "[package.source]",
      'type = "directory"',
      'url = "../local-lib"',
      "",
      "[[package]]",
      'name = "forked"',
      'version = "1.2.3"',
      'category = "main"',
      "optional = false",
      "",
      "[package.source]",
      'type = "git"',
      'url = "https://example.invalid/forked.git"',
      'reference = "main"',
      "",
      "[metadata]",
      'lock-version = "2.0"',
      'python-versions = "^3.9"',
      'content-hash = "0000000000000000000000000000000000000000000000000000000000000000"',
      "",
    ].join("\n");
    const manifest = parsePyprojectDependencies(
      '[tool.poetry.dependencies]\npython = "^3.9"\ndjango = "^3.2"\n[tool.poetry.dev-dependencies]\nPyTest = "^7"\n',
      "pyproject.toml",
    );
    expect(manifest.scopes.get("pytest")).toBe("dev");
    const parsed = parsePoetryLock(lock, "poetry.lock", manifest);
    const by = new Map(parsed.packages.map((pkg) => [pkg.name, pkg]));
    expect([...by.keys()]).toEqual(["Django", "asgiref", "pytest", "argon2-cffi", "forked"]);
    expect(by.get("Django")).toMatchObject({ direct: true, scope: "runtime", line: 3 });
    expect(by.get("asgiref")).toMatchObject({ direct: false, scope: "runtime" });
    expect(by.get("pytest")).toMatchObject({ direct: true, scope: "dev", dev: true });
    expect(by.get("argon2-cffi")).toMatchObject({ direct: false, scope: "optional" });
    expect(parsed.warnings).toEqual([]);
  });

  it("reads poetry 2.x `groups` and propagates scope through the graph when the lock has none", () => {
    const withGroups = [
      "[[package]]",
      'name = "flask"',
      'version = "2.0.0"',
      'groups = ["main"]',
      "[[package]]",
      'name = "ruff"',
      'version = "0.5.0"',
      'groups = ["dev", "lint"]',
      "[[package]]",
      'name = "click"',
      'version = "8.1.0"',
      'groups = ["main", "dev"]',
      "",
    ].join("\n");
    const manifest = parsePyprojectDependencies(
      '[project]\nname = "x"\ndependencies = ["Flask>=2"]\n[dependency-groups]\ndev = ["ruff", {include-group = "lint"}]\nlint = ["ruff"]\n',
      "pyproject.toml",
    );
    expect(
      parsePoetryLock(withGroups, "poetry.lock", manifest).packages.map(
        (pkg) => `${pkg.name}:${pkg.scope}:${pkg.direct}`,
      ),
    ).toEqual(["flask:runtime:true", "ruff:dev:true", "click:runtime:false"]);

    // Poetry 1.5 - 1.8 writes neither `category` nor `groups`.
    const bare = [
      "[[package]]",
      'name = "flask"',
      'version = "2.0.0"',
      "[package.dependencies]",
      'click = ">=8"',
      "[[package]]",
      'name = "click"',
      'version = "8.1.0"',
      "[[package]]",
      'name = "ruff"',
      'version = "0.5.0"',
      "[[package]]",
      'name = "orphan"',
      'version = "1.0"',
      "",
    ].join("\n");
    expect(
      parsePoetryLock(bare, "poetry.lock", manifest).packages.map(
        (pkg) => `${pkg.name}:${pkg.scope}:${pkg.direct}`,
      ),
    ).toEqual([
      "flask:runtime:true",
      "click:runtime:false",
      "ruff:dev:true",
      "orphan:unknown:false",
    ]);
  });

  it("maps pdm.lock groups to runtime, optional and dev using the pyproject.toml", () => {
    const lock = [
      "# This file is @generated by PDM.",
      "# It is not intended for manual editing.",
      "",
      "[metadata]",
      'groups = ["default", "dev", "socks"]',
      'strategy = ["inherit_metadata"]',
      'lock_version = "4.5.0"',
      'content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"',
      "",
      "[[metadata.targets]]",
      'requires_python = ">=3.9"',
      "",
      "[[package]]",
      'name = "requests"',
      'version = "2.19.0"',
      'requires_python = ">=2.7"',
      'summary = "Python HTTP for Humans."',
      'groups = ["default"]',
      "dependencies = [",
      '    "idna<2.8,>=2.5",',
      '    "urllib3<1.24,>=1.21.1",',
      "]",
      "files = [",
      '    {file = "requests-2.19.0-py2.py3-none-any.whl", hash = "sha256:aa"},',
      "]",
      "",
      "[[package]]",
      'name = "requests"',
      'version = "2.19.0"',
      'extras = ["socks"]',
      'groups = ["socks"]',
      "dependencies = [",
      '    "PySocks!=1.5.7,>=1.5.6",',
      '    "requests==2.19.0",',
      "]",
      "",
      "[[package]]",
      'name = "pysocks"',
      'version = "1.7.1"',
      'groups = ["socks"]',
      "",
      "[[package]]",
      'name = "idna"',
      'version = "2.7"',
      'groups = ["default", "dev"]',
      "",
      "[[package]]",
      'name = "pytest"',
      'version = "8.0.0"',
      'groups = ["dev"]',
      'marker = "python_version >= \\"3.8\\""',
      "",
    ].join("\n");
    const manifest = parsePyprojectDependencies(
      [
        "[project]",
        'dependencies = ["requests>=2.19"]',
        "[project.optional-dependencies]",
        'socks = ["requests[socks]"]',
        "[tool.pdm.dev-dependencies]",
        'dev = ["pytest>=8"]',
        "",
      ].join("\n"),
      "pyproject.toml",
    );
    const parsed = parsePdmLock(lock, "pdm.lock", manifest);
    expect(
      parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}:${pkg.scope}:${pkg.direct}`),
    ).toEqual([
      "requests@2.19.0:runtime:true",
      "pysocks@1.7.1:optional:false",
      "idna@2.7:runtime:false",
      "pytest@8.0.0:dev:true",
    ]);
    const lines = lock.split("\n");
    for (const pkg of parsed.packages) {
      expect(lines[pkg.line - 1]).toBe("[[package]]");
      expect(lines[pkg.line]).toBe(`name = "${pkg.name}"`);
    }
    // The first of the two `requests` blocks is the one reported.
    expect(parsed.packages[0]?.line).toBe(lines.indexOf("[[package]]") + 1);
  });

  it("parses PEP 751 pylock files, including named ones, and reports unversioned entries", () => {
    const lock = [
      'lock-version = "1.0"',
      'environments = ["sys_platform == \'linux\'"]',
      'requires-python = ">=3.9"',
      'created-by = "uv"',
      "",
      "[[packages]]",
      'name = "urllib3"',
      'version = "1.24.1"',
      'index = "https://pypi.org/simple"',
      'sdist = { name = "urllib3-1.24.1.tar.gz", url = "https://files.pythonhosted.org/urllib3-1.24.1.tar.gz", hashes = { sha256 = "de" } }',
      "wheels = [",
      '    { name = "urllib3-1.24.1-py2.py3-none-any.whl", url = "https://files.pythonhosted.org/urllib3-1.24.1-py2.py3-none-any.whl", hashes = { sha256 = "61" } },',
      "]",
      "",
      "[[packages]]",
      'name = "from-git"',
      "",
      "[packages.vcs]",
      'type = "git"',
      'url = "https://example.invalid/from-git.git"',
      'commit-id = "0123456789abcdef0123456789abcdef01234567"',
      "",
      "[[packages]]",
      'name = "the-project"',
      "",
      "[packages.directory]",
      'path = "."',
      "editable = true",
      "",
    ].join("\n");
    const root = path.join(temp, "pylock-named");
    writeFile(root, "pylock.dev.toml", lock);
    writeFile(root, "pyproject.toml", '[project]\nname = "the-project"\ndependencies = ["urllib3"]\n');
    const inv = inventory(root);
    expect(inv.lockfiles.map((item) => item.relPath)).toEqual(["pylock.dev.toml"]);
    return runSca({ root, inventory: inv, offline: true }).then((result) => {
      expect(result.packages.map((pkg) => `${pkg.name}@${pkg.version}:${pkg.line}:${pkg.direct}:${pkg.scope}`)).toEqual([
        "urllib3@1.24.1:6:true:runtime",
      ]);
      const text = result.warnings.join("\n");
      expect(text).toContain("pylock.dev.toml: 1 entries without a version");
      // A named pylock file satisfies the pyproject.toml lockfile expectation.
      expect(text).not.toContain("no matching lockfile found");
    });
  });
});

describe("Pipfile.lock (real shape)", () => {
  const lock = JSON.stringify(
    {
      _meta: {
        hash: { sha256: "00" },
        "pipfile-spec": 6,
        requires: { python_version: "3.11" },
        sources: [{ name: "pypi", url: "https://pypi.org/simple", verify_ssl: true }],
      },
      default: {
        requests: {
          hashes: ["sha256:aa", "sha256:bb"],
          index: "pypi",
          markers: "python_version >= '3.7'",
          version: "==2.19.0",
        },
        urllib3: { hashes: ["sha256:cc"], version: "==1.24.1" },
        "from-git": { git: "https://example.invalid/x.git", ref: "abc123" },
        "local-pkg": { editable: true, path: "." },
        loose: { version: ">=1.0" },
      },
      develop: {
        pytest: { hashes: ["sha256:dd"], version: "==5.0.0" },
        urllib3: { hashes: ["sha256:cc"], version: "==1.24.1" },
      },
      docs: {
        sphinx: { version: "==4.0.0" },
      },
    },
    null,
    4,
  );

  it("reads every category, keeps runtime over dev, and reports per-section lines", () => {
    const manifest = parsePipfileDependencies(
      '[[source]]\nurl = "https://pypi.org/simple"\nverify_ssl = true\nname = "pypi"\n\n[packages]\nRequests = "*"\n\n[dev-packages]\npytest = "*"\n\n[docs]\nsphinx = "*"\n\n[requires]\npython_version = "3.11"\n',
      "Pipfile",
    );
    expect([...manifest.names].sort()).toEqual(["pytest", "requests", "sphinx"]);
    const parsed = parsePipfileLock(lock, "Pipfile.lock", manifest);
    const lines = lock.split("\n");
    expect(
      parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}:${pkg.scope}:${pkg.direct}`),
    ).toEqual([
      "requests@2.19.0:runtime:true",
      "urllib3@1.24.1:runtime:false",
      "pytest@5.0.0:dev:true",
      "sphinx@4.0.0:dev:true",
    ]);
    for (const pkg of parsed.packages) {
      expect(lines[pkg.line - 1]?.trim()).toBe(`"${pkg.name}": {`);
    }
    // urllib3 is reported at its `default` entry, not the `develop` one.
    const developStart = lines.findIndex((line) => line.includes('"develop"'));
    expect(parsed.packages.find((pkg) => pkg.name === "urllib3")?.line).toBeLessThan(developStart);
    const text = parsed.warnings.join("\n");
    expect(text).toContain("2 direct URL/VCS entries cannot be checked");
    expect(text).toContain("1 unpinned entries not parsed");
  });

  it("does not throw on JSON that is not a lockfile", () => {
    for (const input of ["[]", "null", "42", '"x"', '{"default": [1], "develop": "x"}', "{"]) {
      const parsed = parsePipfileLock(input, "Pipfile.lock");
      expect(parsed.packages).toEqual([]);
      expect(parsed.warnings.length).toBeGreaterThan(0);
    }
  });
});

describe("requirements files (adversarial)", () => {
  it("never reads an include outside the audit root", () => {
    const base = path.join(temp, "req-jail");
    const root = path.join(base, "root");
    writeFile(base, "outside/secret.txt", "secretpkg==6.6.6\n");
    writeFile(root, "inside.txt", "inside==1.0\n");
    // A file inside the root that an absolute include must NOT be mapped onto.
    writeFile(root, "sub/etc/passwd", "mapped==9.9\n");
    writeFile(root, "etc/passwd", "mapped==9.9\n");
    fs.symlinkSync(path.join(base, "outside/secret.txt"), path.join(root, "link.txt"));
    fs.symlinkSync(path.join(base, "outside"), path.join(root, "linkdir"));
    const content = [
      "-r ../../outside/secret.txt",
      "-r /etc/passwd",
      `-r ${path.join(base, "outside/secret.txt")}`,
      "-r ../link.txt",
      "-r ../linkdir/secret.txt",
      "--requirement=../../outside/secret.txt",
      "-r../../outside/secret.txt",
      "-r ~/secret.txt",
      "-r https://example.invalid/requirements.txt",
      "-r C:\\Users\\x\\requirements.txt",
      "-r ..",
      "-r ../inside.txt",
      "",
    ].join("\n");
    writeFile(root, "sub/requirements.txt", content);
    const parsed = parseRequirements(content, "sub/requirements.txt", {
      root,
      visited: new Set<string>(),
    });
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}:${pkg.file}`)).toEqual([
      "inside@1.0:inside.txt",
    ]);
    const refused = parsed.warnings.filter((warning) =>
      warning.includes("outside the audit root and was not read"),
    );
    expect(refused).toHaveLength(10);
    expect(parsed.warnings.join("\n")).toContain("cannot read include .. (not a regular file)");
  });

  it("handles every include spelling, cycles and repeated includes once", () => {
    const root = path.join(temp, "req-forms");
    writeFile(root, "requirements.txt", [
      "-rbase.txt",
      "--requirement=base.txt",
      '--requirement "extra dir/more.txt"',
      "-r requirements.txt",
      "top==1.0",
      "",
    ].join("\n"));
    writeFile(root, "base.txt", "-r requirements.txt\nbase==2.0\nloose>=1\n");
    writeFile(root, "extra dir/more.txt", "-r ../base.txt\nmore==3.0\n");
    const parsed = parseRequirements(
      fs.readFileSync(path.join(root, "requirements.txt"), "utf8"),
      "requirements.txt",
      { root, visited: new Set<string>() },
    );
    expect(parsed.packages.map((pkg) => `${pkg.name}:${pkg.file}:${pkg.line}`)).toEqual([
      "base:base.txt:2",
      "more:extra dir/more.txt:2",
      "top:requirements.txt:5",
    ]);
    // base.txt was parsed once, so its warning appears once.
    expect(parsed.warnings.filter((warning) => warning.startsWith("base.txt:"))).toHaveLength(1);
  });

  it("parses a file once per scan even when it is scanned and included", async () => {
    const root = path.join(temp, "req-shared");
    writeFile(root, "requirements/base.txt", "django==3.2.0\nloose>=1\n");
    writeFile(root, "requirements/dev.txt", "-r base.txt\npytest==7.0.0\n");
    writeFile(root, "requirements/prod.txt", "-r base.txt\ngunicorn==20.0.0\n");
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    expect(result.packages.map((pkg) => `${pkg.name}:${pkg.file}`).sort()).toEqual([
      "django:requirements/base.txt",
      "gunicorn:requirements/prod.txt",
      "pytest:requirements/dev.txt",
    ]);
    expect(
      result.warnings.filter((warning) => warning.includes("unpinned entries")),
    ).toHaveLength(1);
  });

  it("handles BOM, CRLF, comments, options, extras, markers and multiple clauses", () => {
    const content = [
      "\uFEFFBomFirst==1.0",
      "# comment ending with a backslash \\",
      "after_comment==1.1",
      "spaced  ==  1.2   # trailing comment",
      "hash#in-name-is-not-a-comment==0",
      "extras[a, b]==1.3 ; python_version < '3.9' and extra == 'x'",
      "multi==1.4,!=1.4.1",
      "ranged>=1.0,==1.5",
      "wild==1.*",
      "arbitrary===1.6-local",
      "hashed==1.7 --hash=sha256:aa \\",
      "    --hash=sha256:bb",
      "(paren)==0",
      "legacy (==1.8)",
      "--index-url https://example.invalid/simple",
      "--extra-index-url=https://example.invalid/simple",
      "-c constraints.txt",
      "--constraint=constraints.txt",
      "-e git+https://example.invalid/e.git#egg=e",
      "--editable ./local",
      "-e .",
      "./downloads/pkg-1.0-py3-none-any.whl",
      "pkg-2.0-py3-none-any.whl",
      "vcs @ git+https://example.invalid/vcs.git@v1",
      "extra[x] @ https://example.invalid/extra.whl",
      "file:///srv/pkg.tar.gz",
      "unpinned",
      "Ünïcödé==1.0",
      "",
    ].join("\r\n");
    const parsed = parseRequirements(content, "requirements.txt");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}:${pkg.line}`)).toEqual([
      "BomFirst@1.0:1",
      "after_comment@1.1:3",
      "spaced@1.2:4",
      "extras@1.3:6",
      "multi@1.4:7",
      "ranged@1.5:8",
      "arbitrary@1.6-local:10",
      "hashed@1.7:11",
      "legacy@1.8:14",
    ]);
    expect(parsed.packages.every((pkg) => pkg.scope === "unknown" && pkg.direct)).toBe(true);
    const text = parsed.warnings.join("\n");
    expect(text).toContain("8 direct URL/VCS entries cannot be checked");
    expect(text).toContain("2 unpinned entries not parsed");
  });

  it("does not backtrack on very long lines", () => {
    const spaces = " ".repeat(300_000);
    const content = [
      `a${spaces}b`,
      `${spaces}x`,
      `c==1.0${spaces}# comment`,
      "x#".repeat(200_000),
      "a-".repeat(300_000),
      `d${"[".repeat(200_000)}`,
      `e==${"1,".repeat(200_000)}`,
      `${"f==1 \\\n".repeat(50_000)}`,
      "last==9.9",
    ].join("\n");
    const parsed = within(5_000, () => parseRequirements(content, "requirements.txt"));
    expect(parsed.packages.map((pkg) => pkg.name)).toEqual(
      expect.arrayContaining(["c", "last"]),
    );
  });
});

describe("lockfile detection", () => {
  it("treats *.txt inside a requirements/ directory at any depth as requirements", () => {
    const root = path.join(temp, "inv-nested");
    writeFile(root, "services/api/requirements/prod.txt", "django==3.2.0\n");
    writeFile(root, "services/api/pyproject.toml", '[project]\nname = "api"\ndependencies = ["django"]\n');
    writeFile(root, "requirements/dev.txt", "pytest==7.0.0\n");
    writeFile(root, "docs/notes.txt", "django==1.0\n");
    writeFile(root, "requirements-dev.txt", "ruff==0.5.0\n");
    writeFile(root, "dev-requirements.txt", "mypy==1.0\n");
    const inv = inventory(root);
    expect(inv.lockfiles.map((item) => item.relPath).sort()).toEqual([
      "dev-requirements.txt",
      "requirements-dev.txt",
      "requirements/dev.txt",
      "services/api/requirements/prod.txt",
    ]);
    return runSca({ root, inventory: inv, offline: true }).then((result) => {
      expect(result.packages.map((pkg) => pkg.name).sort()).toEqual([
        "django",
        "mypy",
        "pytest",
        "ruff",
      ]);
      // requirements/prod.txt next to the pyproject.toml counts as its lockfile.
      expect(result.warnings.join("\n")).not.toContain("no matching lockfile found");
    });
  });
});

describe("pyproject.toml direct dependencies and scopes", () => {
  it("covers PEP 621, PEP 735, Poetry (incl. legacy), PDM and uv tables with PEP 503 names", () => {
    const manifest = parsePyprojectDependencies(
      [
        "[project]",
        "dependencies = [",
        '  "Flask_SQLAlchemy>=3",',
        '  "zope.interface ; python_version < \'3.12\'",',
        '  "requests[security,socks] @ https://example.invalid/r.whl",',
        "]",
        "[project.optional-dependencies]",
        'Docs = ["Sphinx"]',
        "[dependency-groups]",
        'test = ["PyTest>=8", {include-group = "lint"}]',
        'lint = ["ruff"]',
        "[tool.poetry.dependencies]",
        'python = "^3.9"',
        'Django = "^4.2"',
        'psycopg2 = { version = "^2.9", optional = true }',
        "[tool.poetry.dev-dependencies]",
        'black = "*"',
        "[tool.poetry.group.docs.dependencies]",
        'mkdocs = "*"',
        "[tool.poetry.extras]",
        'pg = ["psycopg2"]',
        "[tool.pdm.dev-dependencies]",
        'lint = ["flake8"]',
        "[tool.uv]",
        'dev-dependencies = ["coverage[toml]>=7"]',
        "",
      ].join("\n"),
      "pyproject.toml",
    );
    expect(manifest.warning).toBeUndefined();
    expect(Object.fromEntries([...manifest.scopes].sort())).toEqual({
      black: "dev",
      coverage: "dev",
      django: "runtime",
      flake8: "dev",
      "flask-sqlalchemy": "runtime",
      mkdocs: "dev",
      psycopg2: "optional",
      pytest: "dev",
      requests: "runtime",
      ruff: "dev",
      sphinx: "optional",
      "zope-interface": "runtime",
    });
    expect([...manifest.optionalGroups].sort()).toEqual(["docs", "pg"]);
    // PEP 503: FLASK.sqlalchemy in the lock matches Flask_SQLAlchemy in the manifest.
    const parsed = parsePoetryLock(
      '[[package]]\nname = "FLASK.sqlalchemy"\nversion = "3.0"\n[[package]]\nname = "greenlet"\nversion = "1.0"\n',
      "poetry.lock",
      manifest,
    );
    expect(parsed.packages.map((pkg) => pkg.direct)).toEqual([true, false]);
  });

  it("surfaces an unreadable pyproject.toml instead of claiming it is missing", async () => {
    const root = path.join(temp, "pyproject-broken");
    writeFile(root, "poetry.lock", '[[package]]\nname = "django"\nversion = "3.2.0"\n');
    writeFile(root, "pyproject.toml", '[project\nname = "broken"\n');
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    const text = result.warnings.join("\n");
    expect(text).toContain("pyproject.toml: TOML parse failed");
    expect(text).not.toContain("no pyproject.toml found");
    expect(result.packages[0]).toMatchObject({ name: "django", direct: true, scope: "unknown" });
  });

  it("does not read a pyproject.toml that is a symlink leaving the root", async () => {
    const base = path.join(temp, "pyproject-link");
    const root = path.join(base, "root");
    writeFile(base, "outside/pyproject.toml", '[project]\ndependencies = ["django"]\n');
    writeFile(root, "poetry.lock", '[[package]]\nname = "django"\nversion = "3.2.0"\n[[package]]\nname = "sqlparse"\nversion = "0.4.0"\n');
    fs.symlinkSync(path.join(base, "outside/pyproject.toml"), path.join(root, "pyproject.toml"));
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    // Nothing from the outside file is used: both packages stay direct.
    expect(result.packages.map((pkg) => pkg.direct)).toEqual([true, true]);
    expect(result.warnings.join("\n")).toContain("pyproject.toml: manifest was not read");
  });
});

describe("PEP 440 ordering from the specification", () => {
  // "Summary of permitted suffixes and relative ordering" in PEP 440.
  const pepOrder = [
    "1.dev0",
    "1.0.dev456",
    "1.0a1",
    "1.0a2.dev456",
    "1.0a12.dev456",
    "1.0a12",
    "1.0b1.dev456",
    "1.0b2",
    "1.0b2.post345.dev456",
    "1.0b2.post345",
    "1.0rc1.dev456",
    "1.0rc1",
    "1.0",
    "1.0+abc.5",
    "1.0+abc.7",
    "1.0+5",
    "1.0.post456.dev34",
    "1.0.post456",
    "1.0.15",
    "1.1.dev1",
  ];
  // "Version epochs" in PEP 440.
  const epochOrder = ["1.0", "1.1", "2.0", "2013.10", "2014.04", "1!1.0", "1!1.1", "1!2.0"];

  it("orders every pair of the PEP's lists", () => {
    for (const list of [pepOrder, epochOrder]) {
      for (let i = 0; i < list.length; i += 1) {
        for (let j = 0; j < list.length; j += 1) {
          const compared = comparePypiVersions(list[i] as string, list[j] as string);
          expect(Math.sign(compared), `${list[i]} vs ${list[j]}`).toBe(Math.sign(i - j));
        }
      }
      const shuffled = [...list].reverse().sort(comparePypiVersions);
      expect(shuffled).toEqual(list);
    }
  });

  it("treats the PEP's alternate spellings as equal", () => {
    const equal: Array<[string, string]> = [
      ["1.0alpha1", "1.0a1"],
      ["1.0beta2", "1.0b2"],
      ["1.0c1", "1.0rc1"],
      ["1.0pre1", "1.0rc1"],
      ["1.0preview1", "1.0rc1"],
      ["1.1.a1", "1.1a1"],
      ["1.1-a1", "1.1a1"],
      ["1.1_a1", "1.1a1"],
      ["1.1a.1", "1.1a1"],
      ["1.1a-1", "1.1a1"],
      ["1.1a", "1.1a0"],
      ["1.2-post2", "1.2.post2"],
      ["1.2post2", "1.2.post2"],
      ["1.2.post.2", "1.2.post2"],
      ["1.2.post", "1.2.post0"],
      ["1.2-1", "1.2.post1"],
      ["1.0-r4", "1.0.post4"],
      ["1.0-rev4", "1.0.post4"],
      ["1.2-dev2", "1.2.dev2"],
      ["1.2dev2", "1.2.dev2"],
      ["1.2.dev", "1.2.dev0"],
      ["1.0+ubuntu-1", "1.0+ubuntu.1"],
      ["1.0+ubuntu_1", "1.0+ubuntu.1"],
      ["1.0+UBUNTU.1", "1.0+ubuntu.1"],
      ["1.1RC1", "1.1rc1"],
      ["1.0.DEV1", "1.0.dev1"],
      ["v1.0", "1.0"],
      ["V1.0", "1.0"],
      ["  1.0\n", "1.0"],
      ["01.02", "1.2"],
      ["1.0", "1.0.0.0"],
      ["0!1.0", "1.0"],
      ["1.0a1-1.dev2", "1.0a1.post1.dev2"],
    ];
    for (const [left, right] of equal) {
      expect(comparePypiVersions(left, right), `${left} == ${right}`).toBe(0);
      expect(comparePypiVersions(right, left), `${right} == ${left}`).toBe(0);
    }
  });

  it("orders local versions, implicit post releases and huge numbers", () => {
    const ordered: Array<[string, string]> = [
      ["1.0", "1.0-1"],
      ["1.0-1", "1.0-2"],
      ["1.0.post1", "1.0.1.dev0"],
      ["1.0+abc", "1.0+abc.1"],
      ["1.0+abc.5", "1.0+5"],
      ["1.0+1", "1.0+1.1"],
      ["1.0+9", "1.0+10"],
      ["1.0+local", "1.0.post1"],
      ["1.0.dev1", "1.0.dev2"],
      ["1.0.dev99", "1.0a0"],
      ["1.0a1.dev1", "1.0a1"],
      ["1.0a1", "1.0a1.post1"],
      ["1.0rc9", "1.0"],
      ["1.0.9", "1.0.10"],
      ["2!0.1", "3!0.0.1"],
      ["20240101123456789011", "20240101123456789012"],
      ["1.0.post20240101123456789011", "1.0.post20240101123456789012"],
    ];
    for (const [lower, higher] of ordered) {
      expect(comparePypiVersions(lower, higher), `${lower} < ${higher}`).toBeLessThan(0);
      expect(comparePypiVersions(higher, lower), `${higher} > ${lower}`).toBeGreaterThan(0);
    }
  });

  it("never throws on invalid versions and keeps a deterministic total order", () => {
    const invalid = [
      "",
      " ",
      "abc",
      "1.0-",
      "1..0",
      "1.0+",
      "1.0+a..b",
      "french toast",
      "1.0.0-SNAPSHOT",
      "!1.0",
      "1!",
      "1.0a1b2",
      "0f3c1a9",
      "=1.0",
      "1".repeat(300),
      `1.0${"a".repeat(100_000)}`,
      `${"1.".repeat(100_000)}x`,
      "1.0\u0000",
      "١.٠",
    ];
    const valid = ["0", "1.0.dev0", "1.0", "1.0+x", "1!0"];
    const all = [...invalid, ...valid];
    within(5_000, () => {
      for (const a of all) {
        for (const b of all) {
          const ab = comparePypiVersions(a, b);
          const ba = comparePypiVersions(b, a);
          expect(Math.sign(ab) + Math.sign(ba)).toBe(0);
          for (const c of valid) {
            // Transitivity through a valid pivot.
            if (ab < 0 && comparePypiVersions(b, c) < 0) {
              expect(comparePypiVersions(a, c)).toBeLessThan(0);
            }
          }
        }
      }
    });
    for (const bad of invalid) {
      for (const good of valid) expect(comparePypiVersions(bad, good)).toBeLessThan(0);
    }
    const once = [...all].sort(comparePypiVersions);
    const twice = [...all].reverse().sort(comparePypiVersions);
    expect(twice).toEqual(once);
    expect(once.slice(-valid.length)).toEqual(valid);
  });
});

describe("PyPI fixed versions with recorded OSV-shaped advisories", () => {
  // Shapes copied from OSV records: a PYSEC entry carries a GIT range (commit
  // hashes) next to the ECOSYSTEM range; several introduced/fixed pairs share
  // one range.
  const pysecRequests = {
    id: "PYSEC-2018-28",
    aliases: ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
    affected: [
      {
        package: { ecosystem: "PyPI", name: "requests", purl: "pkg:pypi/requests" },
        ranges: [
          {
            type: "GIT",
            repo: "https://github.com/requests/requests",
            events: [
              { introduced: "0" },
              { fixed: "c45d7c49ea75133e52ab22a8e9e13173938e36ff" },
              // An all-digit abbreviated hash parses as a huge "version".
              { fixed: "9912345" },
            ],
          },
          { type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.20.0" }] },
        ],
      },
    ],
  };
  const pysecDjango = {
    id: "PYSEC-2021-109",
    aliases: ["BIT-django-2021-35042", "CVE-2021-35042", "GHSA-xpfp-f569-q3p2"],
    affected: [
      {
        package: { ecosystem: "PyPI", name: "django", purl: "pkg:pypi/django" },
        ranges: [
          {
            type: "ECOSYSTEM",
            events: [
              { introduced: "3.1" },
              { fixed: "3.1.13" },
              { introduced: "3.2" },
              { fixed: "3.2.5" },
            ],
          },
        ],
      },
    ],
  };

  it("ignores GIT ranges and picks the fix of the installed release line", () => {
    expect(
      extractFixedVersion(pysecRequests, { name: "requests", version: "2.19.0", ecosystem: "PyPI" }),
    ).toBe("2.20.0");
    expect(
      extractFixedVersion(pysecDjango, { name: "Django", version: "3.2.0", ecosystem: "PyPI" }),
    ).toBe("3.2.5");
    expect(
      extractFixedVersion(pysecDjango, { name: "django", version: "3.1.0", ecosystem: "PyPI" }),
    ).toBe("3.1.13");
  });

  it("uses PEP 440 order for pre, post, dev, epoch and trailing-zero fixes", () => {
    const fixes = (...fixed: string[]) => ({
      affected: [
        {
          package: { ecosystem: "PyPI", name: "demo" },
          ranges: [{ type: "ECOSYSTEM", events: fixed.map((version) => ({ fixed: version })) }],
        },
      ],
    });
    const pick = (installed: string, ...fixed: string[]) =>
      extractFixedVersion(fixes(...fixed), { name: "Demo", version: installed, ecosystem: "PyPI" });
    // The generic comparator ranks "2.0.dev1" above "2.0a1" and "1.0.0" above "1.0".
    expect(pick("2.0.dev1", "2.0a1", "2.0")).toBe("2.0a1");
    expect(pick("2.0a1", "2.0.dev1", "2.0")).toBe("2.0");
    expect(pick("2.0rc1", "2.0b3", "2.0")).toBe("2.0");
    expect(pick("1.0", "1.0.0", "1.0.0.0")).toBeUndefined();
    expect(pick("1.0", "1.0.0", "1.0.post1")).toBe("1.0.post1");
    expect(pick("v1.0", "1.0.1")).toBe("1.0.1");
    expect(pick("2024.1", "1!1.0", "2025.1")).toBe("2025.1");
    expect(pick("1!1.0", "2025.1", "1!1.1")).toBe("1!1.1");
    expect(pick("1.0+local.1", "1.0", "1.0.1")).toBe("1.0.1");
    expect(pick("1.0", "not-a-version", "1.1")).toBe("1.1");
    // Non-PyPI ecosystems keep the generic comparator.
    expect(
      extractFixedVersion(
        { affected: [{ ranges: [{ type: "SEMVER", events: [{ fixed: "4.17.19" }] }] }] },
        { name: "lodash", version: "4.17.15", ecosystem: "npm" },
      ),
    ).toBe("4.17.19");
  });

  it("uses the PyPI comparator for the same-major upgrade advice", () => {
    // Generic order would call 2.0.dev1 the highest of these.
    expect(recommendUpgrade("2.0.dev0", ["2.0.dev1", "2.0a1"], "PyPI")).toBe("2.0a1");
    expect(recommendUpgrade("1.0", ["1.0.0.post1", "1.0.post2"], "PyPI")).toBe("1.0.post2");
    expect(recommendUpgrade("3.2.0", ["3.2.25", "5.2.17"], "PyPI")).toBe(
      "3.2.25 (same major, 1 open) / 5.2.17 (fixes all)",
    );
  });
});

describe("advisory alias grouping in the built-in OSV path", () => {
  const cvss = (vector: string) => [{ type: "CVSS_V3", score: vector }];
  const details: Record<string, unknown> = {
    "PYSEC-2018-28": {
      id: "PYSEC-2018-28",
      details: "PYSEC text without a summary.",
      aliases: ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
      affected: [
        {
          package: { ecosystem: "PyPI", name: "requests" },
          ranges: [
            { type: "GIT", events: [{ introduced: "0" }, { fixed: "c45d7c49ea75133e52ab22a8e9e13173938e36ff" }] },
          ],
        },
      ],
    },
    "GHSA-x84v-xcm2-53pg": {
      id: "GHSA-x84v-xcm2-53pg",
      summary: "Insufficiently Protected Credentials in Requests",
      aliases: ["CVE-2018-18074"],
      severity: cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
      database_specific: { severity: "HIGH", cwe_ids: ["CWE-522"] },
      affected: [
        {
          package: { ecosystem: "PyPI", name: "requests" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.20.0" }] }],
        },
      ],
    },
    "PYSEC-2023-74": {
      id: "PYSEC-2023-74",
      aliases: ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"],
      severity: cvss("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"),
      affected: [
        {
          package: { ecosystem: "PyPI", name: "requests" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.3.0" }, { fixed: "2.31.0" }] }],
        },
      ],
    },
    "GHSA-j8r2-6x86-q33q": {
      id: "GHSA-j8r2-6x86-q33q",
      summary: "Unintended leak of Proxy-Authorization header in requests",
      aliases: ["CVE-2023-32681"],
      database_specific: { severity: "MODERATE" },
      affected: [
        {
          package: { ecosystem: "PyPI", name: "requests" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.3.0" }, { fixed: "2.31.0" }] }],
        },
      ],
    },
    "PYSEC-2099-1": { id: "PYSEC-2099-1", aliases: ["CVE-2099-0001"], summary: "No GHSA twin" },
    "OSV-2099-7": { id: "OSV-2099-7", summary: "No aliases at all" },
  };
  const client: HttpClient = {
    async postJson(_url, body) {
      const queries = (body as { queries: Array<{ package: { name: string } }> }).queries;
      return {
        results: queries.map((query) =>
          query.package.name === "requests"
            ? { vulns: Object.keys(details).map((id) => ({ id })) }
            : {},
        ),
      };
    },
    async getJson(url) {
      const id = decodeURIComponent(url.slice(url.lastIndexOf("/") + 1));
      return details[id];
    },
  };

  it("emits one finding per vulnerability with the GHSA id preferred", async () => {
    const root = path.join(temp, "alias-groups");
    writeFile(
      root,
      "Pipfile.lock",
      JSON.stringify({ develop: { requests: { version: "==2.19.0" } }, default: { idna: { version: "==3.4" } } }, null, 2),
    );
    const result = await runSca({ root, inventory: inventory(root), http: client });
    expect(result.vulnIds).toHaveLength(6);
    expect(result.findings.map((finding) => finding.advisoryId)).toEqual([
      "GHSA-x84v-xcm2-53pg",
      "GHSA-j8r2-6x86-q33q",
      "PYSEC-2099-1",
      "OSV-2099-7",
    ]);
    const [first, second, third] = result.findings;
    expect(first?.ruleId).toBe("sca-ghsa-x84v-xcm2-53pg");
    expect(first?.aliases).toEqual(["PYSEC-2018-28", "CVE-2018-18074"]);
    expect(first?.title).toContain("Insufficiently Protected Credentials");
    expect(first?.severity).toBe("high");
    expect(first?.cwe).toBe("CWE-522");
    // The PYSEC twin only has a GIT range; the fix comes from the GHSA entry.
    expect(first?.fixedVersion).toBe("2.20.0");
    // Highest severity of the group: the PYSEC CVSS vector (6.1) is medium,
    // equal to the GHSA "MODERATE"; the CVSS score is kept.
    expect(second?.severity).toBe("medium");
    expect(second?.cvss).toBeCloseTo(6.1, 1);
    expect(second?.aliases).toEqual(["PYSEC-2023-74", "CVE-2023-32681"]);
    expect(third?.aliases).toEqual(["CVE-2099-0001"]);
    for (const finding of result.findings) {
      expect(finding.aliases).not.toContain(finding.advisoryId);
      expect(finding.file).toBe("Pipfile.lock");
      expect(finding.startLine).toBe(3);
      expect(finding.dependencyPath).toBe("pipfile dev dependency");
      expect((finding as Record<string, unknown>).dependencyScope).toBe("dev");
    }
  });

  it("groups transitively and keeps unrelated advisories apart", () => {
    const groups = groupAdvisories([
      { id: "A", detail: { aliases: ["X"] } },
      { id: "B", detail: { aliases: ["Y"] } },
      { id: "C", detail: { aliases: ["x", "Y"] } },
      { id: "D" },
      { id: "A", detail: { aliases: ["D"] } },
      { id: "E", detail: { aliases: ["D"] } },
    ]);
    expect(groups.map((group) => group.map((entry) => entry.id))).toEqual([
      ["A", "B", "C"],
      ["D", "E"],
    ]);
    expect(pickAdvisoryId(["PYSEC-1", "CVE-2020-1", "GHSA-aaaa-bbbb-cccc"])).toBe("GHSA-aaaa-bbbb-cccc");
    expect(pickAdvisoryId(["PYSEC-1", "CVE-2020-1"])).toBe("CVE-2020-1");
    expect(pickAdvisoryId(["PYSEC-1", "OSV-2"])).toBe("PYSEC-1");
  });
});

describe("the same release pinned in several lockfiles", () => {
  it("queries OSV once per package but reports a finding for every lockfile", async () => {
    const root = path.join(temp, "multi-lock");
    writeFile(root, "api/requirements.txt", "requests==2.19.0\nflask==2.0.0\n");
    writeFile(root, "worker/requirements.txt", "# worker\n\nRequests==2.19.0\n");
    writeFile(root, "worker/Pipfile.lock", JSON.stringify({ default: { requests: { version: "==2.19.0" } } }));
    const queried: string[] = [];
    const client: HttpClient = {
      async postJson(_url, body) {
        const queries = (body as { queries: Array<{ package: { name: string } }> }).queries;
        for (const query of queries) queried.push(query.package.name);
        return {
          results: queries.map((query) =>
            query.package.name === "requests" ? { vulns: [{ id: "GHSA-x84v-xcm2-53pg" }] } : {},
          ),
        };
      },
      async getJson() {
        return { id: "GHSA-x84v-xcm2-53pg", summary: "s", aliases: ["CVE-2018-18074"] };
      },
    };
    const result = await runSca({ root, inventory: inventory(root), http: client });
    expect(queried.sort()).toEqual(["flask", "requests"]);
    expect(result.queriedPackages).toBe(2);
    expect(result.findings.map((f) => `${f.file}:${f.startLine}`).sort()).toEqual([
      "api/requirements.txt:1",
      "worker/Pipfile.lock:1",
      "worker/requirements.txt:3",
    ]);
    // Distinct fingerprints, so none is dropped by fingerprint dedupe.
    expect(new Set(result.findings.map((f) => f.fingerprint)).size).toBe(3);
  });
});

describe("Python lockfile fixtures (every manager)", () => {
  const managers = ["uv", "pdm", "poetry", "pylock", "pipfile", "requirements"];

  it.each(["vulnerable", "clean"])("parses every %s fixture with direct/transitive and scope", async (kind) => {
    const root = path.join(FIXTURES, kind, "sca/python");
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    const seen = (file: string) =>
      result.packages
        .filter((pkg) => pkg.file === file)
        .map((pkg) => `${pkg.name}:${pkg.direct ? "direct" : "transitive"}:${pkg.scope}`);
    for (const manager of managers) {
      expect(result.packages.some((pkg) => pkg.file.startsWith(`${manager}/`)), manager).toBe(true);
    }
    expect(seen("uv/uv.lock")).toEqual([
      "jinja2:direct:runtime",
      "markupsafe:transitive:runtime",
      "pytest:direct:dev",
    ]);
    expect(seen("pdm/pdm.lock")).toEqual([
      "pytest:direct:dev",
      "pyyaml:direct:runtime",
      "requests:direct:runtime",
      "urllib3:transitive:runtime",
    ]);
    expect(seen("poetry/poetry.lock")).toEqual([
      "jinja2:direct:runtime",
      "markupsafe:transitive:runtime",
      "pytest:direct:dev",
    ]);
    expect(seen("pylock/pylock.toml")).toEqual([
      "requests:direct:runtime",
      "urllib3:transitive:unknown",
    ]);
    expect(seen("pipfile/Pipfile.lock")).toEqual([
      "requests:direct:runtime",
      "urllib3:transitive:runtime",
      "pytest:direct:dev",
    ]);
    expect(seen("requirements/base.txt")).toEqual([
      "jinja2:direct:unknown",
      "markupsafe:direct:unknown",
    ]);
    expect(result.packages.some((pkg) => pkg.name === "myapp")).toBe(false);
    // Constraints files are never parsed as dependencies.
    expect(result.packages.some((pkg) => pkg.file.endsWith("constraints.txt"))).toBe(false);
    const text = result.warnings.join("\n");
    expect(text).not.toContain("TOML parse failed");
    expect(text).not.toContain("no pyproject.toml found");
    expect(text).not.toContain("no matching lockfile found");
    // Every reported line really is where the package is declared.
    for (const pkg of result.packages) {
      const lines = fs.readFileSync(path.join(root, pkg.file), "utf8").split("\n");
      const window = lines.slice(pkg.line - 1, pkg.line + 1).join("\n").toLowerCase();
      expect(window, `${pkg.file}:${pkg.line}`).toContain(pkg.name.toLowerCase());
    }
  });
});

// ---------------------------------------------------------------------------
// Rust: Cargo.lock and Cargo.toml.
// ---------------------------------------------------------------------------

const CRATES_IO = 'source = "registry+https://github.com/rust-lang/crates.io-index"';

function cargoPackage(name: string, version: string, source?: string, deps: string[] = []): string {
  return [
    "[[package]]",
    `name = "${name}"`,
    `version = "${version}"`,
    ...(source ? [source] : []),
    ...(deps.length > 0 ? ["dependencies = [", ...deps.map((d) => ` "${d}",`), "]"] : []),
    "",
  ].join("\n");
}

function cargoLock(...blocks: string[]): string {
  return ["# This file is automatically @generated by Cargo.", "version = 4", "", ...blocks].join(
    "\n",
  );
}

describe("Cargo.lock parser", () => {
  it("returns crates.io packages with ecosystem, manager and header line", () => {
    const content = cargoLock(
      cargoPackage("app", "0.1.0", undefined, ["serde"]),
      cargoPackage("serde", "1.0.130", CRATES_IO),
      cargoPackage("sparse-crate", "2.0.0", 'source = "sparse+https://index.crates.io/"'),
    );
    const result = parseCargoLock(content, "Cargo.lock");
    expect(result.packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "serde@1.0.130",
      "sparse-crate@2.0.0",
    ]);
    const serde = result.packages[0];
    expect(serde?.ecosystem).toBe("crates.io");
    expect(serde?.manager).toBe("cargo");
    expect(serde?.file).toBe("Cargo.lock");
    expect(content.split("\n")[(serde?.line ?? 0) - 1]).toBe("[[package]]");
    expect(content.split("\n")[serde?.line ?? 0]).toBe('name = "serde"');
    // Dispatched by file name.
    expect(parseLockfile("sub/Cargo.lock", content).packages).toHaveLength(2);
  });

  it("skips local crates and counts git and other-registry crates in one warning each", () => {
    const result = parseCargoLock(
      cargoLock(
        cargoPackage("local", "0.1.0"),
        cargoPackage("g1", "1.0.0", 'source = "git+https://github.com/x/g1?rev=abc#abc"'),
        cargoPackage("g2", "1.0.0", 'source = "git+https://github.com/x/g2#def"'),
        cargoPackage("alt", "1.0.0", 'source = "registry+https://my-company.example/index"'),
        cargoPackage("alt2", "1.0.0", 'source = "sparse+https://my-company.example/index/"'),
        cargoPackage("serde", "1.0.0", CRATES_IO),
      ),
      "Cargo.lock",
    );
    expect(result.packages.map((p) => p.name)).toEqual(["serde"]);
    const git = result.warnings.filter((w) => w.includes("git repositories"));
    expect(git).toEqual(["Cargo.lock: 2 crate(s) from git repositories cannot be checked against OSV"]);
    expect(result.warnings.filter((w) => w.includes("registries other than crates.io"))).toEqual([
      "Cargo.lock: 2 crate(s) from registries other than crates.io were not checked against OSV",
    ]);
  });

  it("keeps two versions of the same crate", () => {
    const result = parseCargoLock(
      cargoLock(
        cargoPackage("rand", "0.7.3", CRATES_IO),
        cargoPackage("rand", "0.8.5", CRATES_IO),
      ),
      "Cargo.lock",
    );
    expect(result.packages.map((p) => p.version)).toEqual(["0.7.3", "0.8.5"]);
  });

  it("never throws on malformed input and falls back to a line scan", () => {
    for (const content of [
      "",
      "[[package]]\nname = ",
      "\u0000\u0001garbage",
      "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n" + CRATES_IO + "\nbroken = [\n",
    ]) {
      expect(() => parseCargoLock(content, "Cargo.lock")).not.toThrow();
    }
    const fallback = parseCargoLock(
      "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n" + CRATES_IO + "\nbroken = [\n",
      "Cargo.lock",
    );
    expect(fallback.packages.map((p) => `${p.name}@${p.version}:${p.ecosystem}`)).toEqual([
      "serde@1.0.0:crates.io",
    ]);
    expect(fallback.warnings.some((w) => w.includes("line-based fallback"))).toBe(true);
    expect(parseCargoLock("", "Cargo.lock").warnings).toContain(
      "Cargo.lock: no parseable cargo dependencies found",
    );
  });

  it("treats every crate as direct with a warning when there is no Cargo.toml", () => {
    const result = parseCargoLock(cargoLock(cargoPackage("serde", "1.0.0", CRATES_IO)), "Cargo.lock");
    expect(result.packages[0]?.direct).toBe(true);
    expect(result.packages[0]?.scope).toBe("unknown");
    expect(result.warnings.some((w) => w.includes("no Cargo.toml found"))).toBe(true);
  });
});

describe("Cargo.toml dependencies", () => {
  const manifest = [
    "[package]",
    'name = "app"',
    'version = "0.1.0"',
    "",
    "[dependencies]",
    'serde = "1"',
    'my-dep = "0.1"',
    'renamed = { package = "real_name", version = "1" }',
    "",
    "[dependencies.tokio]",
    'version = "1"',
    'features = ["full"]',
    "",
    "[build-dependencies]",
    'cc = "1"',
    "",
    "[dev-dependencies]",
    'rand = "0.7"',
    "",
    "[target.'cfg(windows)'.dependencies]",
    'winapi = "0.3"',
    "",
    "[target.'cfg(unix)'.dev-dependencies]",
    'libc = "0.2"',
    "",
    "[workspace.dependencies]",
    'proc-macro2 = "1"',
    "",
  ].join("\n");

  it("reads every dependency table with its scope", () => {
    const deps = parseCargoManifestDependencies(manifest, "Cargo.toml");
    expect(deps.warning).toBeUndefined();
    expect(Object.fromEntries([...deps.scopes].sort())).toEqual({
      cc: "runtime",
      libc: "dev",
      "my-dep": "runtime",
      "proc-macro2": "unknown",
      rand: "dev",
      "real-name": "runtime",
      serde: "runtime",
      tokio: "runtime",
      winapi: "runtime",
    });
  });

  it("marks direct crates and propagates scope through the lockfile graph", () => {
    const lock = cargoLock(
      cargoPackage("app", "0.1.0", undefined, ["serde", "my_dep", "rand"]),
      cargoPackage("serde", "1.0.0", CRATES_IO, ["shared"]),
      cargoPackage("my_dep", "0.1.0", CRATES_IO),
      cargoPackage("real_name", "1.0.0", CRATES_IO),
      cargoPackage("rand", "0.7.0", CRATES_IO, ["rand_core 0.5.1", "shared"]),
      cargoPackage("rand_core", "0.5.1", CRATES_IO),
      cargoPackage("shared", "1.0.0", CRATES_IO),
      cargoPackage("libc", "0.2.0", CRATES_IO),
      cargoPackage("proc-macro2", "1.0.0", CRATES_IO),
      cargoPackage("plain", "1.0.0", CRATES_IO),
    );
    const result = parseCargoLock(
      lock,
      "Cargo.lock",
      parseCargoManifestDependencies(manifest, "Cargo.toml"),
    );
    const seen = Object.fromEntries(
      result.packages.map((p) => [p.name, `${p.direct ? "direct" : "transitive"}:${p.scope}`]),
    );
    expect(seen).toEqual({
      serde: "direct:runtime",
      my_dep: "direct:runtime",
      real_name: "direct:runtime",
      rand: "direct:dev",
      rand_core: "transitive:dev",
      // Reached from both a runtime and a dev crate: runtime wins.
      shared: "transitive:runtime",
      libc: "direct:dev",
      "proc-macro2": "direct:unknown",
      plain: "transitive:unknown",
    });
    expect(result.packages.find((p) => p.name === "rand")?.dev).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it("reads workspace members and their workspace = true dependencies", async () => {
    const root = path.join(FIXTURES, "vulnerable/sca/rust");
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    expect(
      result.packages.map((p) => `${p.name}:${p.direct ? "direct" : "transitive"}:${p.scope}`).sort(),
    ).toEqual([
      "libc:transitive:runtime",
      "serde:direct:runtime",
      "smallvec:direct:dev",
      "time:direct:runtime",
    ]);
    const text = result.warnings.join("\n");
    expect(text).not.toContain("no matching lockfile found");
    expect(text).not.toContain("no Cargo.toml found");
    // The member's Cargo.toml shares the workspace Cargo.lock: no hotspot.
    expect(manifestLockfileIssues(inventory(root))).toEqual([]);
  });

  it("does not trust a Cargo.toml that links outside the audit root", async () => {
    const outer = path.join(temp, "cargo-symlink");
    const root = path.join(outer, "project");
    writeFile(outer, "outside.toml", '[dependencies]\nserde = "1"\n');
    writeFile(root, "Cargo.lock", cargoLock(cargoPackage("serde", "1.0.0", CRATES_IO)));
    fs.symlinkSync(path.join(outer, "outside.toml"), path.join(root, "Cargo.toml"));
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    expect(result.packages[0]?.scope).toBe("unknown");
    expect(result.packages[0]?.direct).toBe(true);
    expect(result.warnings.some((w) => w.includes("Cargo.toml: manifest was not read"))).toBe(true);
  });

  it("flags a crate Cargo.toml with no Cargo.lock anywhere above it", () => {
    const root = path.join(temp, "cargo-nolock");
    writeFile(root, "lib/Cargo.toml", '[package]\nname = "lib"\n\n[dependencies]\nserde = "1"\n');
    expect(manifestLockfileIssues(inventory(root))).toEqual([
      { file: "lib/Cargo.toml", line: 4, manifest: "Cargo.toml" },
    ]);
  });
});

describe("Cargo.lock scan", () => {
  it("turns a vulnerable crate into a crates.io finding with a fixed version", async () => {
    const root = path.join(temp, "cargo-scan");
    writeFile(root, "Cargo.toml", '[package]\nname = "app"\n\n[dependencies]\ntime = "0.1"\n');
    writeFile(
      root,
      "Cargo.lock",
      cargoLock(
        cargoPackage("app", "0.1.0", undefined, ["time"]),
        cargoPackage("time", "0.1.43", CRATES_IO),
      ),
    );
    const queries: unknown[] = [];
    const http: HttpClient = {
      async postJson(_url, body) {
        const batch = (body as { queries: unknown[] }).queries;
        queries.push(...batch);
        return { results: batch.map(() => ({ vulns: [{ id: "RUSTSEC-2020-0071" }] })) };
      },
      async getJson() {
        return {
          id: "RUSTSEC-2020-0071",
          aliases: ["GHSA-wcg3-cvx6-7396", "CVE-2020-26235"],
          summary: "Potential segfault in the time crate",
          affected: [
            {
              package: { name: "time", ecosystem: "crates.io" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0.0.0-0" }, { fixed: "0.2.23-alpha.1" }, { fixed: "0.2.23" }],
                },
              ],
            },
          ],
        };
      },
    };
    const result = await runSca({ root, inventory: inventory(root), http, sleep: async () => {} });
    expect(queries).toEqual([{ package: { name: "time", ecosystem: "crates.io" }, version: "0.1.43" }]);
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding?.ecosystem).toBe("crates.io");
    expect(finding?.package).toBe("time");
    expect(finding?.file).toBe("Cargo.lock");
    // SemVer: the pre-release sorts before the release, so it is the smallest fix.
    expect(finding?.fixedVersion).toBe("0.2.23-alpha.1");
    expect(finding?.dependencyScope).toBe("runtime");
    expect(String(finding?.dependencyPath)).toContain("direct");
  });

  it("orders versions by SemVer", () => {
    const sorted = ["1.0.0", "1.0.0-alpha.10", "1.0.0-alpha.2", "1.0.0-beta", "0.9.9", "1.0.0+build", "1.0.0-alpha"]
      .slice()
      .sort(compareSemver);
    expect(sorted).toEqual([
      "0.9.9",
      "1.0.0-alpha",
      "1.0.0-alpha.2",
      "1.0.0-alpha.10",
      "1.0.0-beta",
      "1.0.0",
      "1.0.0+build",
    ]);
    expect(compareSemver("1.0.0", "1.0.0+build")).toBe(0);
  });
});

// Regression tests from the adversarial review of the Cargo support.
describe("Cargo workspaces (review regressions)", () => {
  const scopes = async (root: string) => {
    const result = await runSca({ root, inventory: inventory(root), offline: true });
    return {
      result,
      seen: Object.fromEntries(
        result.packages.map((p) => [p.name, `${p.direct ? "direct" : "transitive"}:${p.scope}`]),
      ),
    };
  };
  const workspaceLock = (member: string, memberDeps: string[], extra: string[] = []) =>
    cargoLock(
      cargoPackage("app", "0.1.0", undefined, ["smallvec"]),
      cargoPackage(member, "0.1.0", undefined, memberDeps),
      cargoPackage("smallvec", "0.6.9", CRATES_IO),
      ...extra,
    );

  it.each([
    ['["./crates/helper"]', "crates/helper"],
    ['["crates/helper/"]', "crates/helper"],
    ['["bin/helper"]', "bin/helper"],
    ['["vendor/helper"]', "vendor/helper"],
    ['["crates/[h]elper"]', "crates/helper"],
  ])("keeps a runtime crate of member %s at runtime", async (members, dir) => {
    const root = path.join(temp, `cargo-member-${dir.replace(/\W/g, "_")}-${members.length}`);
    writeFile(
      root,
      "Cargo.toml",
      `[package]\nname = "app"\n\n[workspace]\nmembers = ${members}\n\n[dev-dependencies]\nsmallvec = "0.6"\n`,
    );
    writeFile(root, `${dir}/Cargo.toml`, '[package]\nname = "helper"\n\n[dependencies]\nsmallvec = "0.6"\n');
    writeFile(root, "Cargo.lock", workspaceLock("helper", ["smallvec"]));
    const { seen } = await scopes(root);
    expect(seen.smallvec).toBe("direct:runtime");
  });

  it("does not follow a member's dev-dependencies as runtime", async () => {
    const root = path.join(temp, "cargo-member-dev");
    writeFile(
      root,
      "Cargo.toml",
      '[package]\nname = "app"\n\n[workspace]\nmembers = ["crates/core"]\n\n[dependencies]\ncore = { path = "crates/core" }\n',
    );
    writeFile(
      root,
      "crates/core/Cargo.toml",
      '[package]\nname = "core"\n\n[dependencies]\nserde = "1"\n\n[dev-dependencies]\nproptest = "1"\n',
    );
    writeFile(
      root,
      "Cargo.lock",
      cargoLock(
        cargoPackage("app", "0.1.0", undefined, ["core"]),
        cargoPackage("core", "0.1.0", undefined, ["proptest", "serde"]),
        cargoPackage("proptest", "1.0.0", CRATES_IO),
        cargoPackage("serde", "1.0.0", CRATES_IO),
      ),
    );
    const { seen } = await scopes(root);
    expect(seen).toEqual({ proptest: "direct:dev", serde: "direct:runtime" });
  });

  it("treats what an unread path crate uses as runtime", async () => {
    const root = path.join(temp, "cargo-path-dep");
    writeFile(
      root,
      "Cargo.toml",
      '[package]\nname = "app"\n\n[dependencies]\nmylib = { path = "../mylib" }\n\n[dev-dependencies]\nsmallvec = "0.6"\n',
    );
    writeFile(
      root,
      "Cargo.lock",
      cargoLock(
        cargoPackage("app", "0.1.0", undefined, ["mylib", "smallvec"]),
        cargoPackage("mylib", "0.1.0", undefined, ["smallvec"]),
        cargoPackage("smallvec", "0.6.9", CRATES_IO),
      ),
    );
    const { seen } = await scopes(root);
    expect(seen.smallvec).toBe("direct:runtime");
  });

  it("excludes members by path prefix", async () => {
    const root = path.join(temp, "cargo-exclude");
    writeFile(
      root,
      "Cargo.toml",
      '[workspace]\nmembers = ["crates/*", "crates/legacy/*"]\nexclude = ["crates/legacy"]\n',
    );
    writeFile(root, "crates/a/Cargo.toml", '[package]\nname = "a"\n\n[dependencies]\nserde = "1"\n');
    writeFile(root, "crates/legacy/old/Cargo.toml", '[package]\nname = "old"\n\n[dependencies]\nlibc = "0.2"\n');
    writeFile(
      root,
      "Cargo.lock",
      cargoLock(
        cargoPackage("a", "0.1.0", undefined, ["serde"]),
        cargoPackage("serde", "1.0.0", CRATES_IO),
        cargoPackage("libc", "0.2.0", CRATES_IO),
      ),
    );
    const { seen } = await scopes(root);
    expect(seen).toEqual({ serde: "direct:runtime", libc: "transitive:unknown" });
    // The excluded crate has no lockfile of its own.
    expect(manifestLockfileIssues(inventory(root)).map((i) => i.file)).toEqual([
      "crates/legacy/old/Cargo.toml",
    ]);
  });

  it("still flags a nested Cargo.toml that is not a workspace member", () => {
    const root = path.join(temp, "cargo-fuzz");
    writeFile(root, "Cargo.toml", '[package]\nname = "app"\n\n[dependencies]\nserde = "1"\n');
    writeFile(root, "Cargo.lock", cargoLock(cargoPackage("serde", "1.0.0", CRATES_IO)));
    writeFile(
      root,
      "fuzz/Cargo.toml",
      '[package]\nname = "app-fuzz"\n\n[workspace]\nmembers = ["."]\n\n[dependencies]\nlibfuzzer-sys = "0.4"\n',
    );
    expect(manifestLockfileIssues(inventory(root)).map((i) => i.file)).toEqual(["fuzz/Cargo.toml"]);
  });

  it.each([
    ['[package]\nname = "app"\n\n[dependencies]\nmylib = { path = "mylib" }\n', "mylib"],
    ['[package]\nname = "app"\n\n[workspace]\n\n[dependencies]\nmylib = { path = "crates/mylib" }\n', "crates/mylib"],
  ])("does not flag an implicit path-dependency member (%#)", (rootManifest, dir) => {
    const root = path.join(temp, `cargo-implicit-${dir.replace(/\W/g, "_")}`);
    writeFile(root, "Cargo.toml", rootManifest);
    writeFile(root, `${dir}/Cargo.toml`, '[package]\nname = "mylib"\n\n[dependencies]\nserde = "1"\n');
    writeFile(
      root,
      "Cargo.lock",
      cargoLock(
        cargoPackage("app", "0.1.0", undefined, ["mylib"]),
        cargoPackage("mylib", "0.1.0", undefined, ["serde"]),
        cargoPackage("serde", "1.0.0", CRATES_IO),
      ),
    );
    expect(manifestLockfileIssues(inventory(root))).toEqual([]);
  });

  it("never labels a crate dev in the line-based fallback", () => {
    const manifest = parseCargoManifestDependencies(
      '[package]\nname = "app"\n\n[dependencies]\nfoo = "1"\n\n[dev-dependencies]\nsmallvec = "0.6"\n',
      "Cargo.toml",
    );
    const lock = cargoLock(
      cargoPackage("foo", "1.0.0", CRATES_IO, ["smallvec"]),
      cargoPackage("smallvec", "0.6.9", CRATES_IO),
      '[[package]]\nname = "broken\n',
    );
    const result = parseCargoLock(lock, "Cargo.lock", manifest);
    expect(result.warnings.some((w) => w.includes("line-based fallback"))).toBe(true);
    expect(result.packages.find((p) => p.name === "smallvec")?.scope).toBe("unknown");
    expect(result.packages.find((p) => p.name === "smallvec")?.dev).toBeUndefined();
  });

  it("reads a v1 lockfile with [root] and [metadata] checksums", () => {
    const lock = [
      "[root]",
      'name = "app"',
      'version = "0.1.0"',
      'dependencies = [\n "libc 0.2.40 (registry+https://github.com/rust-lang/crates.io-index)",\n]',
      "",
      "[[package]]",
      'name = "libc"',
      'version = "0.2.40"',
      CRATES_IO,
      "",
      "[metadata]",
      '"checksum libc 0.2.40 (registry+https://github.com/rust-lang/crates.io-index)" = "abc"',
      "",
    ].join("\n");
    const result = parseCargoLock(lock, "Cargo.lock");
    expect(result.packages.map((p) => `${p.name}@${p.version}`)).toEqual(["libc@0.2.40"]);
  });

  it("does not warn about a lockfile that holds only local crates", () => {
    const result = parseCargoLock(cargoLock(cargoPackage("app", "0.1.0")), "Cargo.lock");
    expect(result.packages).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it("parses the workspace manifest once for many nested crates", () => {
    const root = path.join(temp, "cargo-many-nested");
    const filler = Array.from({ length: 5000 }, (_, i) => `k${i} = "${"x".repeat(40)}"`).join("\n");
    writeFile(root, "Cargo.toml", `[package]\nname = "app"\n\n[package.metadata.big]\n${filler}\n`);
    writeFile(root, "Cargo.lock", cargoLock(cargoPackage("app", "0.1.0")));
    for (let i = 0; i < 300; i += 1) {
      writeFile(root, `n${i}/Cargo.toml`, `[package]\nname = "n${i}"\n`);
    }
    const inv = inventory(root);
    const started = Date.now();
    expect(manifestLockfileIssues(inv)).toHaveLength(300);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("matches many member globs quickly", async () => {
    const root = path.join(temp, "cargo-many-globs");
    const members = Array.from({ length: 20_000 }, (_, i) => `"g${i}/*"`).join(", ");
    writeFile(root, "Cargo.toml", `[workspace]\nmembers = [${members}]\n`);
    for (let i = 0; i < 50; i += 1) {
      writeFile(root, `x${i}/Cargo.toml`, `[package]\nname = "x${i}"\n`);
    }
    writeFile(root, "Cargo.lock", cargoLock(cargoPackage("serde", "1.0.0", CRATES_IO)));
    const started = Date.now();
    await runSca({ root, inventory: inventory(root), offline: true });
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

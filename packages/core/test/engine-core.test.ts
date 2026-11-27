/**
 * Engine features: file types routed to rules, the literal prefilter, inline
 * suppression semantics and redaction fixes.
 */
import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { detectLanguage } from "../src/language.js";
import { passesPrefilter, requiredLiterals } from "../src/prefilter.js";
import {
  LINE_MASK_ALL,
  LINE_MASK_STRINGS,
  LINE_PLAIN,
  redactLine,
  sensitiveLines,
  splitLines,
} from "../src/redact.js";
import { loadRules, scanRules, type RuleHit, type RuleSet } from "../src/rules.js";
import { scanSecrets } from "../src/secrets.js";
import { CLEAN, RULES_DIR, VULNERABLE, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("engine-core");
afterAll(() => cleanup(temp));

const ruleSet = loadRules(RULES_DIR);

let counter = 0;
function project(files: Record<string, string>): string {
  counter += 1;
  const root = path.join(temp, `case-${counter}`);
  for (const [rel, content] of Object.entries(files)) writeFile(root, rel, content);
  return root;
}

function customRules(yaml: string): RuleSet {
  counter += 1;
  const dir = path.join(temp, `rules-${counter}`);
  writeFile(dir, "r.yml", yaml);
  return loadRules(dir);
}

function keys(hits: RuleHit[]): string[] {
  return hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`);
}

describe("file types routed to rules", () => {
  it("detects the configuration, script, template and agent-instruction languages", () => {
    const cases: Record<string, string> = {
      ".codex/config.toml": "toml",
      "uv.toml": "toml",
      "pyproject.toml": "toml",
      "tox.ini": "ini",
      "setup.cfg": "ini",
      ".npmrc": "ini",
      "pip.conf": "ini",
      ".pypirc": "ini",
      "src/main/resources/application.properties": "properties",
      "scripts/build.sh": "shell",
      "x.bash": "shell",
      "x.zsh": "shell",
      ".cursorrules": "markdown",
      ".windsurfrules": "markdown",
      ".clinerules": "markdown",
      ".rules": "markdown",
      ".cursor/rules/a.mdc": "markdown",
      "templates/index.html": "template",
      "a.htm": "template",
      "a.jinja2": "template",
      "a.j2": "template",
      "App.vue": "template",
      "App.svelte": "template",
      "v.ejs": "template",
      "v.hbs": "template",
      "v.mustache": "template",
      "mapper/UserMapper.xml": "xml",
      "web.config": "xml",
      "requirements.txt": "requirements",
      "requirements/dev.txt": "requirements",
      "constraints.in": "requirements",
      "notes.txt": "unknown",
      "Makefile": "unknown",
      "udev/50-x.rules": "unknown",
    };
    const actual = Object.fromEntries(Object.keys(cases).map((file) => [file, detectLanguage(file)]));
    expect(actual).toEqual(cases);
  });

  it("gives the new languages an inventory kind and counts their lines", () => {
    const root = project({
      "a.toml": "x = 1\n",
      "b.ini": "[s]\nx=1\n",
      "c.properties": "x=1\n",
      "d.sh": "echo hi\n",
      "e.html": "<p>hi</p>\n",
      ".cursorrules": "Be brief.\n",
    });
    const inv = inventory(root);
    const kinds = Object.fromEntries(inv.files.map((file) => [file.relPath, file.kind]));
    expect(kinds).toEqual({
      "a.toml": "config",
      "b.ini": "config",
      "c.properties": "config",
      "d.sh": "source",
      "e.html": "source",
      ".cursorrules": "doc",
    });
    expect(inv.languages.shell).toEqual({ files: 1, loc: 2 });
    expect(inv.languages.template).toEqual({ files: 1, loc: 2 });
  });

  it("keeps the web.config rules on .config files when other XML is routed too", () => {
    const xml = '<configuration><system.web><compilation debug="true" /></system.web></configuration>\n';
    const root = project({ "web.config": xml, "mapper/settings.xml": xml });
    const hits = scanRules(inventory(root).files, ruleSet).hits;
    expect(keys(hits)).toEqual(["web.config:1:cs-config-debug-compilation"]);
  });

  it("still finds secrets in files of every new language", () => {
    const token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const files = ["deploy.sh", "config.toml", "app.ini", "app.properties", "index.html", ".npmrc"];
    const root = project(Object.fromEntries(files.map((file) => [file, `token = "${token}"\n`])));
    const found = scanSecrets(inventory(root).files).findings.map((finding) => finding.file).sort();
    expect([...new Set(found)]).toEqual([...files].sort());
  });
});

describe("literal prefilter", () => {
  it("derives the required literals of a pattern", () => {
    const of = (source: string, flags = "i"): string[] | undefined =>
      requiredLiterals(source, flags)?.literals.slice().sort();
    expect(of("\\bstrcpy\\s*\\(")).toEqual(["strcpy"]);
    expect(of("\\b(?:Process\\.Start|ShellExecute)\\b")).toEqual(["process.start", "shellexecute"]);
    expect(of("\\bProcess\\.Start", "")).toEqual(["Process.Start"]);
    // The longest mandatory run wins over a short one.
    expect(of("\\bos\\.system\\s*\\(\\s*request\\.args")).toEqual(["request.args"]);
    // An optional part is not required; a part repeated at least once is.
    expect(of("(?:foo)?barbaz")).toEqual(["barbaz"]);
    expect(of("(?:xyz)+")).toEqual(["xyz"]);
    expect(of("abc?d")).toEqual(undefined); // "ab" and "d": too short
    expect(of("abcd?efg")).toEqual(["abc"]);
    // A branch without literals makes the whole alternation unconstrained.
    expect(of("strcpy|\\w+\\(")).toBeUndefined();
    // Lookarounds, classes and white space add nothing.
    expect(of("(?<=password)\\s*=\\s*[\"']")).toBeUndefined();
    expect(of("import\\s+pickle")).toEqual(["import"]);
    // Constructs it does not understand: no prefilter.
    expect(of("abc", "iu")).toBeUndefined();
    expect(of("(?i:abc)def", "")).toBeUndefined();
    // A literal "{" that is not a quantifier, and an escaped one.
    expect(of("\\$\\{\\{\\s*github")).toEqual(["github"]);
    expect(of("x{2}yyy")).toEqual(["yyy"]);
  });

  /** Every line of every fixture file, and variants built to defeat the prefilter. */
  function corpus(): string[] {
    const lines: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(abs);
        else if (entry.isFile() && fs.statSync(abs).size < 512 * 1024) {
          for (const line of splitLines(fs.readFileSync(abs, "utf8"))) {
            if (line.trim().length > 0 && line.length <= 2000) lines.push(line);
          }
        }
      }
    };
    walk(VULNERABLE);
    walk(CLEAN);
    const variants: string[] = [];
    let seed = 7;
    const random = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    for (const line of lines) {
      // Case changes, non-ASCII look-alikes, white space and comment markers.
      variants.push(line.toUpperCase(), line.toLowerCase());
      variants.push([...line].map((ch) => (random() < 0.3 ? ch.toUpperCase() : ch)).join(""));
      variants.push(line.replace(/s/g, "\u017f").replace(/k/g, "\u212a").replace(/i/g, "\u0130"));
      variants.push(line.replace(/\s+/g, "\t"), `/* x */ ${line} // y`);
    }
    return [...lines, ...variants];
  }

  it("never rules out a line the rule's patterns match (every built-in rule, fixtures and adversarial variants)", () => {
    const lines = corpus();
    expect(lines.length).toBeGreaterThan(10_000);
    const violations: string[] = [];
    let filtered = 0;
    for (const rule of ruleSet.rules) {
      const prefilter = rule.compiled.prefilter;
      if (!prefilter) continue;
      filtered += 1;
      const patterns = [rule.compiled.pattern, ...(rule.compiled.patterns ?? [])].filter(
        (pattern): pattern is RegExp => pattern !== undefined,
      );
      for (const line of lines) {
        if (passesPrefilter(prefilter, line, line.toLowerCase())) continue;
        // Ruled out: then no pattern of the rule may match.
        if (patterns.every((pattern) => pattern.test(line))) {
          violations.push(`${rule.id}: ${line.slice(0, 120)}`);
        }
      }
    }
    expect(filtered).toBeGreaterThan(ruleSet.rules.length * 0.9);
    expect(violations).toEqual([]);
  }, 300_000);

  it("changes no result of a scan of the fixtures", () => {
    for (const root of [VULNERABLE, CLEAN]) {
      const files = inventory(root).files;
      const view = (prefilter: boolean): string[] => {
        const result = scanRules(files, ruleSet, { prefilter });
        return [
          ...result.hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.evidence}`),
          ...result.suppressed.map((entry) => `S:${entry.file}:${entry.line}:${entry.ruleId}`),
          ...[...result.redactions].map(([file, lines]) => `R:${file}:${JSON.stringify([...lines])}`),
        ].sort();
      };
      const on = view(true);
      expect(on.length).toBeGreaterThan(0);
      expect(on).toEqual(view(false));
    }
  }, 120_000);

  it("is sound on text that comments, blanks and joined lines turn into a unit", () => {
    // Python joins a bracketed call over lines and blanks the comment; C#
    // blanks comments too. The file-level check must still keep the rule.
    const root = project({
      "a.py": "import os\nos.system(  # run it\n    request.args['c'])\n",
      "b.cs": "var p = Process.Start(/* x */ Request.Query[\"c\"]);\n",
    });
    const files = inventory(root).files;
    const on = keys(scanRules(files, ruleSet).hits);
    expect(on).toEqual(keys(scanRules(files, ruleSet, { prefilter: false }).hits));
    expect(on.length).toBeGreaterThan(0);
  });
});

describe("inline suppression", () => {
  const grouped = customRules(
    [
      "rules:",
      "  - id: t-exec-request",
      "    title: t",
      "    title_zh: t",
      "    severity: high",
      "    confidence: high",
      "    cwe: CWE-78",
      "    languages: [python]",
      "    pattern: 'os\\.system\\(\\s*request\\.'",
      "    group: t-exec",
      "    message: m",
      "    remediation: r",
      "  - id: t-exec-api",
      "    title: t",
      "    title_zh: t",
      "    severity: medium",
      "    confidence: low",
      "    kind: hotspot",
      "    cwe: CWE-78",
      "    languages: [python]",
      "    pattern: 'os\\.system\\('",
      "    group: t-exec",
      "    message: m",
      "    remediation: r",
      "",
    ].join("\n"),
  );

  it("suppresses the group's result when the ignore names the winning rule (no runner-up)", () => {
    const root = project({
      "a.py": "os.system(request.args['c'])  # code-audit:ignore t-exec-request -- reviewed\n",
    });
    const result = scanRules(inventory(root).files, grouped);
    expect(keys(result.hits)).toEqual([]);
    expect(result.suppressed.map((entry) => entry.ruleId)).toEqual(["t-exec-request"]);
  });

  it("does not suppress a higher-ranked hit when the ignore names only the fallback", () => {
    const root = project({
      "a.py": "os.system(request.args['c'])  # code-audit:ignore t-exec-api -- reviewed\n",
    });
    const result = scanRules(inventory(root).files, grouped);
    expect(keys(result.hits)).toEqual(["a.py:1:t-exec-request"]);
  });

  it("honours an ignore on any line of a multi-line statement, the last included", () => {
    // A trailing ignore belongs to its own statement, not to the next one; a
    // comment on a line of its own applies to the statement that follows.
    const root = project({
      "a.py": [
        "os.system(",
        "    request.args['c'],",
        ")  # code-audit:ignore t-exec-request -- reviewed",
        "os.system(",
        "    request.args['d'],",
        ")",
        "# code-audit:ignore t-exec-request -- reviewed",
        "os.system(request.args['e'])",
        "",
      ].join("\n"),
    });
    const result = scanRules(inventory(root).files, grouped);
    expect(keys(result.hits)).toEqual(["a.py:4:t-exec-request"]);
    expect(result.suppressed.map((entry) => `${entry.line}:${entry.ruleId}`)).toEqual([
      "1:t-exec-request",
      "8:t-exec-request",
    ]);
    // --no-inline-ignore / --untrusted: every comment is ignored.
    const all = scanRules(inventory(root).files, grouped, { inlineIgnore: false });
    expect(keys(all.hits)).toEqual(["a.py:1:t-exec-request", "a.py:4:t-exec-request", "a.py:8:t-exec-request"]);
    expect(all.suppressed).toEqual([]);
  });
});

describe("redaction", () => {
  it("masks what a withinKeys rule with redactEvidence matched (structured path)", () => {
    const rules = customRules(
      [
        "rules:",
        "  - id: t-literal-token",
        "    title: t",
        "    title_zh: t",
        "    severity: high",
        "    confidence: high",
        "    cwe: CWE-798",
        "    languages: [yaml]",
        "    withinKeys: [deploy_key]",
        "    redactEvidence: true",
        "    pattern: '(?<secret>[A-Za-z0-9]{20,})'",
        "    message: m",
        "    remediation: r",
        "",
      ].join("\n"),
    );
    const value = "Zq8VbN3kLmP0xYt7RwS2uJ";
    const root = project({
      "ci.yml": `jobs:\n  a:\n    deploy_key: ${value}\n    other: |\n      deploy_key\n`,
      "folded.yml": `x:\n  deploy_key: >-\n    ${value}\n    ${value.toLowerCase()}\n`,
    });
    const result = scanRules(inventory(root).files, rules);
    expect(keys(result.hits).sort()).toEqual(["ci.yml:3:t-literal-token", "folded.yml:2:t-literal-token"]);
    for (const hit of result.hits) {
      expect(hit.evidence).not.toContain(value);
      expect(hit.evidence.toLowerCase()).not.toContain(value.toLowerCase());
    }
    expect(result.redactions.get("ci.yml")?.get(3)).toBeDefined();
  });

  it("masks only the values of secret-like keys inside a settings section named like a secret", () => {
    const lines = [
      "{",
      '  "AuthServer": {',
      '    "Authority": "https://login.example.com",',
      '    "ClientId": "web-app",',
      '    "ClientSecret": "Xy7-very-secret-value",',
      '    "Scopes": [ "openid" ]',
      "  },",
      '  "Passwords": {',
      '    "admin": "hunter2-admin-pw"',
      "  }",
      "}",
    ];
    const flags = sensitiveLines(lines);
    expect(flags[2]).toBe(LINE_PLAIN);
    expect(flags[3]).toBe(LINE_PLAIN);
    expect(redactLine(lines[2] as string, { file: "appsettings.json" })).toContain("https://login.example.com");
    expect(redactLine(lines[4] as string, { file: "appsettings.json" })).not.toContain("Xy7-very-secret-value");
    // A strongly secret-like section still masks every string in it.
    expect(flags[8]).toBe(LINE_MASK_STRINGS);
  });

  it("does not mask setting words, algorithm names, class paths or the flag after a flag", () => {
    expect(redactLine('  http_tokens = "optional"', { file: "main.tf" })).toBe('  http_tokens = "optional"');
    expect(redactLine("    secrets: inherit", { file: "ci.yml" })).toBe("    secrets: inherit");
    expect(redactLine("gcloud run deploy api --allow-unauthenticated --region us-central1")).toBe(
      "gcloud run deploy api --allow-unauthenticated --region us-central1",
    );
    expect(redactLine('JWT_ALGORITHM = "HS256"')).toBe('JWT_ALGORITHM = "HS256"');
    const jwtLine = redactLine('token = jwt.encode(payload, "s3cr3t-signing-key-0042", algorithm="HS256")');
    expect(jwtLine).not.toContain("s3cr3t-signing-key-0042");
    expect(jwtLine).toContain('algorithm="HS256"');
    const hashers = ["PASSWORD_HASHERS = [", '    "django.contrib.auth.hashers.PBKDF2PasswordHasher",', "]"];
    expect(sensitiveLines(hashers)[1]).toBe(LINE_PLAIN);
    // Real values stay masked.
    expect(redactLine('http_token = "abcd1234efgh5678"')).not.toContain("abcd1234efgh5678");
    expect(redactLine("secrets: hunter2hunter2", { file: "ci.yml" })).not.toContain("hunter2hunter2");
    expect(redactLine("deploy --auth-token Tk9a8b7c6d5e4f3")).not.toContain("Tk9a8b7c6d5e4f3");
    expect(redactLine('PASSWORD = "correct.horse.battery.staple"')).not.toContain("battery");
    const secretList = ["PASSWORDS = [", '    "hunter2-admin-pw",', "]"];
    expect(sensitiveLines(secretList)[1]).toBe(LINE_MASK_STRINGS);
  });

  it("ends a private-key block at the first line that is not key material", () => {
    const code = [
      'if (pem.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {',
      "  return decrypt(pem, passphrase);",
      "}",
      ...Array.from({ length: 500 }, (_, index) => `const value${index} = compute(${index});`),
    ];
    const flags = sensitiveLines(code);
    expect([...flags].filter((flag) => flag === LINE_MASK_ALL)).toEqual([]);

    const body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7";
    const embedded = [
      'const KEY = "-----BEGIN PRIVATE KEY-----\\n" +',
      `  "${body}\\n" +`,
      `  "${body}\\n" +`,
      '  "-----END PRIVATE KEY-----\\n";',
      "const next = 1;",
    ];
    expect([...sensitiveLines(embedded)]).toEqual([0, LINE_MASK_ALL, LINE_MASK_ALL, LINE_MASK_ALL, 0]);

    // No END marker: the body is still masked, the code after it is not.
    const truncated = ["-----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED", "", body, `${body.slice(0, 20)}==`, "", "done();"];
    expect([...sensitiveLines(truncated)]).toEqual([0, LINE_MASK_ALL, LINE_MASK_ALL, LINE_MASK_ALL, LINE_MASK_ALL, LINE_MASK_ALL, 0]);
  });
});

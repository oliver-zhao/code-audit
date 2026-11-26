import path from "node:path";
import fs from "node:fs";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { loadRules, localizeRule, scanRules } from "../src/rules.js";
import {
  RULES_DIR,
  VULNERABLE,
  cleanup,
  loadExpected,
  makeTempDir,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("rules");

afterAll(() => cleanup(temp));

describe("rule loading", () => {
  it("loads every bundled rule with required metadata", () => {
    const ruleSet = loadRules(RULES_DIR);
    expect(ruleSet.rules.length).toBeGreaterThanOrEqual(50);
    for (const rule of ruleSet.rules) {
      expect(rule.id).toMatch(/^[a-z0-9-]+$/);
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
      expect(rule.remediation.length).toBeGreaterThan(5);
      expect(["critical", "high", "medium", "low", "info"]).toContain(
        rule.severity,
      );
      expect(["high", "medium", "low"]).toContain(rule.confidence);
      expect(rule.title_zh).toBeTruthy();
      expect(rule.languages.length).toBeGreaterThan(0);
    }
  });

  it("localizes rule text to Chinese and falls back to English", () => {
    const rule = loadRules(RULES_DIR).rules.find(
      (candidate) => candidate.id === "cs-sql-injection",
    );
    expect(rule).toBeDefined();
    if (!rule) return;
    expect(localizeRule(rule, "en").title).toBe(rule.title);
    expect(localizeRule(rule, "zh").title).toBe(rule.title_zh);
    expect(localizeRule({ ...rule, title_zh: undefined }, "zh").title).toBe(
      rule.title,
    );
  });

  it("reports the file name for an invalid rule", () => {
    const rulesDir = path.join(temp, "bad-rules");
    writeFile(
      rulesDir,
      "bad.yml",
      [
        "rules:",
        "  - id: broken-rule",
        "    title: Broken",
        "    severity: high",
        "    languages: [python]",
        "    pattern: 'x'",
        "    message: missing cwe",
        "    remediation: fix it",
        "",
      ].join("\n"),
    );
    expect(() => loadRules(rulesDir)).toThrow(/bad\.yml/);
    expect(() => loadRules(rulesDir)).toThrow(/cwe/);
  });
});

describe("rule coverage of fixtures", () => {
  const ruleSet = loadRules(RULES_DIR);
  const expected = loadExpected();
  const inv = inventory(VULNERABLE);
  const result = scanRules(inv.files, ruleSet);
  const hits = new Set(
    result.hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`),
  );

  it("has a matching fixture seed for every bundled rule", () => {
    const seedRuleIds = new Set(expected.seeds.map((seed) => seed.ruleId));
    const missing = ruleSet.rules
      .map((rule) => rule.id)
      .filter((id) => !seedRuleIds.has(id));
    expect(missing).toEqual([]);
  });

  it("matches every EXPECTED.json seed at the expected line", () => {
    // Seeds for scanner-emitted hotspots (for example dep-missing-lockfile,
    // which the rule engine no longer owns) are covered by scan.test.ts.
    const ruleIds = new Set(ruleSet.rules.map((rule) => rule.id));
    const missing = expected.seeds
      .filter((seed) => ruleIds.has(seed.ruleId))
      .map(
        (seed) => `${seed.file}:${seed.line}:${seed.ruleId}`,
      )
      .filter((key) => !hits.has(key));
    expect(missing).toEqual([]);
  });

  it("supports inline code-audit:ignore with a reason", () => {
    const project = path.join(temp, "suppressed");
    writeFile(
      project,
      "app.py",
      [
        "import os",
        'os.system("ls " + command)  # code-audit:ignore py-command-injection py-os-system-api -- test fixture',
        "",
      ].join("\n"),
    );
    const projectInv = inventory(project);
    const suppressionResult = scanRules(projectInv.files, ruleSet);
    expect(suppressionResult.hits).toHaveLength(0);
    expect(suppressionResult.suppressed).toHaveLength(2);
    expect(suppressionResult.suppressed[0]).toMatchObject({
      ruleId: "py-command-injection",
      file: "app.py",
      line: 2,
      reason: "test fixture",
    });
    expect(fs.existsSync(path.join(project, "app.py"))).toBe(true);
  });
});

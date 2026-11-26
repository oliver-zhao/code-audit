import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { escapeMarkdown, recommendUpgrade } from "../src/report.js";
import { scanProject, type ScanResult } from "../src/scan.js";
import type { HttpClient } from "../src/sca.js";
import {
  VULNERABLE,
  cleanup,
  makeTempDir,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("report");
const out = path.join(temp, "out");
const zhOut = path.join(temp, "out-zh");
let result: ScanResult;
let report: string;
let zhResult: ScanResult;
let zhReport: string;

const CJK = /[\u4e00-\u9fff]/;

beforeAll(async () => {
  result = await scanProject({
    root: VULNERABLE,
    out,
    offline: true,
    formats: ["md", "json", "sarif"],
  });
  report = fs.readFileSync(path.join(result.runDir, "report.md"), "utf8");
  zhResult = await scanProject({
    root: VULNERABLE,
    out: zhOut,
    offline: true,
    formats: ["md", "json", "sarif"],
    lang: "zh",
  });
  zhReport = fs.readFileSync(path.join(zhResult.runDir, "report.md"), "utf8");
});

afterAll(() => cleanup(temp));

describe("SARIF output", () => {
  it("is valid SARIF 2.1.0 with rules, locations and fingerprints", () => {
    const sarif = JSON.parse(
      fs.readFileSync(path.join(result.runDir, "results.sarif"), "utf8"),
    );
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-2.1.0");
    expect(Array.isArray(sarif.runs)).toBe(true);
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("code-audit");
    expect(run.tool.driver.rules.length).toBeGreaterThanOrEqual(70);
    expect(run.tool.driver.rules.map((rule: { id: string }) => rule.id)).toContain(
      "cs-sql-injection",
    );
    expect(run.results).toHaveLength(
      result.findings.length + result.hotspots.length,
    );
    for (const sarifResult of run.results) {
      expect(sarifResult.ruleId).toBeTruthy();
      expect(typeof sarifResult.ruleIndex).toBe("number");
      expect(["high", "medium", "low"]).toContain(
        sarifResult.properties.confidence,
      );
      expect(["finding", "hotspot"]).toContain(sarifResult.properties.kind);
      expect(["sast", "secrets", "sca", "config"]).toContain(sarifResult.properties.category);
      // Not suppressed in this run: an explicit empty array, never absent.
      expect(sarifResult.suppressions).toEqual([]);
      if (sarifResult.properties.kind === "hotspot") {
        expect(sarifResult.level).toBe("note");
      }
      expect(sarifResult.rank).toBeGreaterThan(0);
      expect(sarifResult.rank).toBeLessThanOrEqual(100);
      expect(sarifResult.locations).toHaveLength(1);
      const location = sarifResult.locations[0].physicalLocation;
      expect(location.artifactLocation.uri).toBeTruthy();
      expect(location.region.startLine).toBeGreaterThan(0);
      expect(location.region.snippet.text.length).toBeGreaterThan(0);
      expect(sarifResult.partialFingerprints.primaryLocationLineHash).toMatch(
        /^[a-f0-9]{64}$/,
      );
    }
  });

  it("stays in English even when the Markdown report is Chinese", () => {
    const sarif = JSON.parse(
      fs.readFileSync(path.join(zhResult.runDir, "results.sarif"), "utf8"),
    );
    expect(CJK.test(JSON.stringify(sarif))).toBe(false);
  });
});

describe("Markdown report", () => {
  it("defaults to English and contains no CJK characters", () => {
    expect(report).toContain("Source Code Security Audit Report");
    expect(report).toContain("## 1. Executive Summary");
    expect(report).toContain("## 5. Review hotspots");
    expect(report).toContain("### Remediation priorities");
    expect(report).toContain("Candidate results, not reviewed");
    expect(CJK.test(report)).toBe(false);
  });

  it("renders Chinese section headings with --lang zh", () => {
    expect(zhReport).toContain("## 1. 执行摘要");
    expect(zhReport).toContain("## 5. 复核热点");
    expect(zhReport).toContain("### 修复优先级");
    // Same structure in both languages.
    const sections = (text: string): string[] =>
      text.split("\n").filter((line) => line.startsWith("## ")).map((line) => line.slice(0, 5));
    expect(sections(zhReport)).toEqual(sections(report));
    expect(zhReport.split("\n").length).toBe(report.split("\n").length);
    expect(CJK.test(zhReport)).toBe(true);
  });

  it("escapes HTML and Markdown link injection from repository data", () => {
    expect(report).not.toContain("<script>");
    expect(report).not.toContain("](javascript:");
    expect(report).toContain("injection/&lt;script&gt;alert.md");
    expect(report).toContain("&lt;script&gt;alert");
  });

  it("escapes dangerous strings in helper output", () => {
    const escaped = escapeMarkdown("x ](javascript:alert(1)) <script>");
    expect(escaped).not.toContain("<script>");
    expect(escaped).not.toContain("](javascript:");
  });

  it("lists the rules that fired in the appendix and points to SARIF for the rest", () => {
    const start = report.indexOf("Appendix: Rules triggered in this run");
    expect(start).toBeGreaterThan(0);
    const appendix = report.slice(start);
    const fired = new Set([...result.findings, ...result.hotspots].map((finding) => finding.ruleId));
    const listed = appendix
      .split("\n")
      .filter((line) => line.startsWith("| ") && !line.startsWith("| ---") && !line.startsWith("| Rule ID"))
      .map((line) => (line.split(" | ")[0] ?? "").slice(2).replace(/\\/g, ""));
    const bundled = new Set(listed);
    expect(listed.length).toBeGreaterThan(10);
    for (const ruleId of listed) expect(fired.has(ruleId), ruleId).toBe(true);
    for (const ruleId of ["cs-sql-injection", "dockerfile-no-user"]) {
      expect(bundled.has(ruleId), ruleId).toBe(true);
    }
    expect(appendix).toMatch(/\d+ rules were loaded; only the \d+ that produced a finding or hotspot are listed/);
    // The complete list stays available in SARIF.
    const sarif = JSON.parse(
      fs.readFileSync(path.join(result.runDir, "results.sarif"), "utf8"),
    );
    const sarifRules = sarif.runs[0].tool.driver.rules.map((rule: { id: string }) => rule.id);
    expect(sarifRules).toContain("prompt-injection-ignore");
    expect(sarifRules.length).toBeGreaterThan(listed.length);
  });


  it("aggregates multiple advisories for one package into one row", async () => {
    const project = path.join(temp, "sca-report");
    writeFile(
      project,
      "package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app", version: "1.0.0" },
          "node_modules/lodash": { version: "4.17.15" },
        },
      }),
    );
    const client: HttpClient = {
      async postJson(_url, body) {
        const queries = (body as { queries: unknown[] }).queries;
        return {
          results: queries.map(() => ({
            vulns: [{ id: "GHSA-agg-1" }, { id: "GHSA-agg-2" }],
          })),
        };
      },
      async getJson(url) {
        const id = url.endsWith("GHSA-agg-1") ? "GHSA-agg-1" : "GHSA-agg-2";
        return {
          id,
          summary: `Advisory ${id}`,
          database_specific: { severity: "CRITICAL" },
          affected: [
            {
              ranges: [
                {
                  events: [
                    { fixed: id === "GHSA-agg-1" ? "4.17.19" : "4.17.21" },
                  ],
                },
              ],
            },
          ],
        };
      },
    };
    const scaScan = await scanProject({
      root: project,
      out: path.join(temp, "sca-report-out"),
      offline: false,
      formats: ["md", "json"],
      http: client,
    });
    const scaReport = fs.readFileSync(
      path.join(scaScan.runDir, "report.md"),
      "utf8",
    );
    const rows = scaReport.split("\n").filter((line) => line.startsWith("| lodash "));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatch(
      /^\| lodash \| 4\.17\.15 \| \S+ \| \S+ \| 2 \| critical \| 4\.17\.21 \| GHSA-agg-1, GHSA-agg-2 \| package-lock\.json:\d+ \|$/,
    );
  });
});

describe("upgrade recommendation", () => {
  it("keeps a single version when the highest fix is in the same major", () => {
    expect(recommendUpgrade("4.17.15", ["4.17.19", "4.17.21"])).toBe("4.17.21");
  });

  it("shows both the same-major fix and the version that fixes all", () => {
    const recommendation = recommendUpgrade("3.2.0", ["3.2.25", "5.2.17"]);
    expect(recommendation).toContain("3.2.25 (same major");
    expect(recommendation).toContain("5.2.17 (fixes all)");
  });

  it("reports when no same-major version fixes everything", () => {
    const recommendation = recommendUpgrade("3.2.0", ["5.2.17"]);
    expect(recommendation).toContain("5.2.17");
    expect(recommendation).toContain("fixes all");
    expect(recommendation).toContain("no same-major fix");
  });
});

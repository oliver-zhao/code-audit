import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { scanProject, type ScanResult } from "../src/scan.js";
import {
  CLEAN,
  VULNERABLE,
  cleanup,
  loadExpected,
  makeTempDir,
  readAllOutputFiles,
} from "./helpers.js";

const temp = makeTempDir("scan");
const vulnerableOut = path.join(temp, "vulnerable-out");
const cleanOut = path.join(temp, "clean-out");
let vulnerable: ScanResult;
let clean: ScanResult;

beforeAll(async () => {
  vulnerable = await scanProject({
    root: VULNERABLE,
    out: vulnerableOut,
    offline: true,
    formats: ["md", "json", "sarif"],
  });
  clean = await scanProject({
    root: CLEAN,
    out: cleanOut,
    offline: true,
    formats: ["md", "json", "sarif"],
  });
});

afterAll(() => cleanup(temp));

describe("seed vulnerability recall", () => {
  it("matches every EXPECTED.json seed with the declared kind", () => {
    const expected = loadExpected();
    const findingKeys = new Set(
      vulnerable.findings.map(
        (finding) => `${finding.file}:${finding.startLine}:${finding.ruleId}`,
      ),
    );
    const hotspotKeys = new Set(
      vulnerable.hotspots.map(
        (hotspot) => `${hotspot.file}:${hotspot.startLine}:${hotspot.ruleId}`,
      ),
    );
    const missing = expected.seeds
      .filter((seed) =>
        seed.kind === "hotspot"
          ? !hotspotKeys.has(`${seed.file}:${seed.line}:${seed.ruleId}`)
          : !findingKeys.has(`${seed.file}:${seed.line}:${seed.ruleId}`),
      )
      .map((seed) => `${seed.file}:${seed.line}:${seed.ruleId}`);
    expect(missing).toEqual([]);
  });

  it("has no findings on the clean fixtures and only low-confidence hotspots", () => {
    expect(clean.findings).toEqual([]);
    expect(clean.hotspots.length).toBeGreaterThan(0);
    for (const hotspot of clean.hotspots) {
      expect(hotspot.confidence).toBe("low");
      expect(hotspot.kind).toBe("hotspot");
    }
  });
});

describe("confidence and API-only rules", () => {
  it("keeps only the higher-confidence hit for same-line pairs", () => {
    const pairs: Array<{
      file: string;
      line: number;
      taint: string;
      api: string;
    }> = [
      { file: "python/app.py", line: 14, taint: "py-sql-injection", api: "py-sql-api" },
      { file: "python/app.py", line: 15, taint: "py-command-injection", api: "py-os-system-api" },
      { file: "csharp/Program.cs", line: 15, taint: "cs-sql-injection", api: "cs-sql-api" },
      { file: "java/App.java", line: 12, taint: "java-sql-injection", api: "java-sql-api" },
      { file: "java/App.java", line: 13, taint: "java-command-injection", api: "java-exec-api" },
      { file: "javascript/app.js", line: 9, taint: "js-sql-injection", api: "js-sql-api" },
      { file: "go/main.go", line: 15, taint: "go-sql-injection", api: "go-sql-api" },
      { file: "cpp/app.cpp", line: 11, taint: "cpp-system", api: "cpp-system-api" },
    ];
    for (const pair of pairs) {
      const findingIds = vulnerable.findings
        .filter(
          (finding) =>
            finding.file === pair.file && finding.startLine === pair.line,
        )
        .map((finding) => finding.ruleId);
      const hotspotIds = vulnerable.hotspots
        .filter(
          (hotspot) =>
            hotspot.file === pair.file && hotspot.startLine === pair.line,
        )
        .map((hotspot) => hotspot.ruleId);
      expect(findingIds).toContain(pair.taint);
      expect(findingIds).not.toContain(pair.api);
      expect(hotspotIds).not.toContain(pair.api);
    }
  });

  it("reports API-only matches as low-confidence hotspots", () => {
    const apiHotspots = vulnerable.hotspots.filter(
      (hotspot) => hotspot.file === "api/python/app.py",
    );
    expect(apiHotspots.map((hotspot) => hotspot.ruleId).sort()).toEqual([
      "py-os-system-api",
      "py-path-api",
      "py-sql-api",
    ]);
    for (const hotspot of apiHotspots) {
      expect(hotspot.confidence).toBe("low");
      expect(hotspot.kind).toBe("hotspot");
    }
  });

  it("uses only high/medium/low for every finding and hotspot", () => {
    for (const finding of [
      ...vulnerable.findings,
      ...vulnerable.hotspots,
      ...clean.findings,
      ...clean.hotspots,
    ]) {
      expect(["high", "medium", "low"]).toContain(finding.confidence);
    }
  });
});
describe("secret handling", () => {
  const originals = [
    "AKIAFAKEFIXTURE00000",
    "ghp_FAKEFIXTURE0000000000000000000000000",
    "xoxb-FAKE0000-FAKE0000-FAKEFIXTUREONLY",
    "Fake-Password-For-Fixture-Only-2026",
    "FakeApiKeyForFixtureOnly0000",
    "MIIBOgIBAAJBAKfakeKeyMaterialForCodeAuditFixtureOnly000000000000000",
    "-----BEGIN RSA PRIVATE KEY-----",
  ];

  it("never writes fixture secret literals to any output file", () => {
    const output = readAllOutputFiles(vulnerableOut);
    for (const secret of originals) {
      expect(output).not.toContain(secret);
    }
  });

  it("reports the seeded secrets with redacted evidence", () => {
    const aws = vulnerable.findings.find(
      (finding) =>
        finding.ruleId === "secret-aws-access-key" &&
        finding.file === "secrets/secrets.txt",
    );
    expect(aws).toBeDefined();
    // The public AKIA prefix stays; of the key itself only the last 2
    // characters do.
    expect(aws?.evidence).toMatch(/AKIA\*{14}[0-9A-Z]{2}(?![0-9A-Z])/);
    expect(aws?.evidence).not.toContain("FAKEFIXTURE");
  });

  it("reports an obvious placeholder with low confidence and skips an environment reference", () => {
    const generic = vulnerable.findings
      .filter(
        (finding) =>
          finding.ruleId === "secret-generic-assignment" &&
          finding.file === "secrets/secrets.txt",
      )
      .sort((a, b) => a.startLine - b.startLine);
    // Line 6 is `password = "changeme"`: never dropped, low confidence.
    // Line 7 is `api_key = "${API_KEY}"`: a reference, not a secret.
    expect(generic.map((finding) => `${finding.startLine}:${finding.confidence}`)).toEqual([
      "4:high",
      "5:high",
      "6:low",
    ]);
    expect(generic[2]?.confidenceOriginal).toBe("high");
    expect(generic[2]?.adjustments).toEqual(["placeholder-value"]);
    expect(generic[0]?.adjustments).toBeUndefined();
  });

  it("keeps the private key body out of every output", () => {
    const document = JSON.parse(
      fs.readFileSync(path.join(vulnerable.runDir, "findings.json"), "utf8"),
    ) as {
      schemaVersion: number;
      run: { runId: string; findingCounts: Record<string, number> };
      findings: Array<{ ruleId: string; evidence: string }>;
    };
    expect(document.schemaVersion).toBe(1);
    expect(document.run.runId).toBe(vulnerable.runId);
    expect(document.run.findingCounts).toBeDefined();
    const privateKey = document.findings.find(
      (finding) => finding.ruleId === "secret-private-key",
    );
    expect(privateKey?.evidence).toContain("redacted");
  });
});

describe("external engine wiring", () => {
  it("marks external engines missing when no tool is installed", () => {
    const statuses = new Map(
      vulnerable.coverage.engines.map((engine) => [engine.name, engine.status]),
    );
    expect(statuses.get("opengrep")).toBe("missing");
    expect(statuses.get("osv-scanner")).toBe("missing");
    expect(statuses.get("gitleaks")).toBe("missing");
    expect(statuses.get("builtin-rules")).toBe("ok");
  });

  it("disables external engines when --no-external selects only builtin", async () => {
    const result = await scanProject({
      root: VULNERABLE,
      out: path.join(temp, "builtin-only-out"),
      offline: true,
      formats: ["json"],
      engines: ["builtin"],
    });
    const statuses = new Map(
      result.coverage.engines.map((engine) => [engine.name, engine.status]),
    );
    expect(statuses.get("opengrep")).toBe("disabled");
    expect(statuses.get("osv-scanner")).toBe("disabled");
    expect(statuses.get("gitleaks")).toBe("disabled");
    expect(statuses.get("builtin-rules")).toBe("ok");
  });
});

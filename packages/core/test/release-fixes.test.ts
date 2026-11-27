import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { detectLanguage } from "../src/language.js";
import { inventory } from "../src/inventory.js";
import { scanProject } from "../src/scan.js";
import { cleanup, makeTempDir, writeFile } from "./helpers.js";

// Regressions from the end-to-end release review of 0.3.0.
const temp = makeTempDir("release-fixes");
afterAll(() => cleanup(temp));

describe("Dockerfile name routing", () => {
  it("keeps the language of a known extension after a dockerfile. prefix", () => {
    expect(detectLanguage("Dockerfile")).toBe("dockerfile");
    expect(detectLanguage("Dockerfile.prod")).toBe("dockerfile");
    expect(detectLanguage("docker/Dockerfile.dev")).toBe("dockerfile");
    expect(detectLanguage("api.Dockerfile")).toBe("dockerfile");
    expect(detectLanguage("dockerfile.py")).toBe("python");
    expect(detectLanguage("src/lexers/dockerfile.ts")).toBe("typescript");
    expect(detectLanguage("rules/iac/dockerfile.yml")).toBe("yaml");
    expect(detectLanguage("Dockerfile.md")).toBe("markdown");
  });

  it("reports Python findings in dockerfile.py", async () => {
    const root = path.join(temp, "dockerfile-py");
    writeFile(root, "dockerfile.py", 'import os\nfrom flask import request\nos.system("ls " + request.args["x"])\n');
    const result = await scanProject({ root, offline: true, engines: ["builtin"], noBaseline: true, noIgnoreFile: true });
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids.some((id) => id.startsWith("py-"))).toBe(true);
    expect(ids.some((id) => id.startsWith("dockerfile-"))).toBe(false);
  });
});

describe("path filters ignore case", () => {
  it("applies the .NET configuration rules to WEB.CONFIG and AppSettings.json", async () => {
    const root = path.join(temp, "case");
    writeFile(root, "WEB.CONFIG", '<configuration>\n  <system.web>\n    <customErrors mode="Off" />\n  </system.web>\n</configuration>\n');
    writeFile(root, "AppSettings.json", '{\n  "DetailedErrors": true\n}\n');
    const result = await scanProject({ root, offline: true, engines: ["builtin"], noBaseline: true, noIgnoreFile: true });
    const files = new Set([...result.findings, ...result.hotspots].map((f) => f.file));
    expect(files.has("WEB.CONFIG")).toBe(true);
    expect(files.has("AppSettings.json")).toBe(true);
  });
});

describe("Cargo src/bin", () => {
  it("reads src/bin but still skips a top-level bin directory", () => {
    const root = path.join(temp, "cargo-bin");
    writeFile(root, "src/bin/tool.rs", "fn main() {}\n");
    writeFile(root, "bin/tool.sh", "echo hi\n");
    fs.mkdirSync(path.join(root, "src"), { recursive: true });
    const rels = inventory(root).files.map((f) => f.relPath);
    expect(rels).toContain("src/bin/tool.rs");
    expect(rels).not.toContain("bin/tool.sh");
  });
});

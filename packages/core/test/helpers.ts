import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
export const RULES_DIR = path.join(REPO_ROOT, "rules");
export const FIXTURES = path.join(REPO_ROOT, "fixtures");
export const VULNERABLE = path.join(FIXTURES, "vulnerable");
export const CLEAN = path.join(FIXTURES, "clean");
export const CLI = path.join(REPO_ROOT, "packages/cli/dist/index.js");

export interface ExpectedSeed {
  file: string;
  line: number;
  ruleId: string;
  language: string;
  kind?: "finding" | "hotspot";
}

export interface ExpectedOpengrepHit {
  file: string;
  line: number;
  ruleId: string;
  confidence: string;
}

export interface ExpectedFile {
  vulnerableRoot: string;
  seeds: ExpectedSeed[];
  opengrep?: ExpectedOpengrepHit[];
}

export function loadExpected(): ExpectedFile {
  return JSON.parse(
    fs.readFileSync(path.join(VULNERABLE, "EXPECTED.json"), "utf8"),
  ) as ExpectedFile;
}

export function makeTempDir(prefix = "case"): string {
  return fs.mkdtempSync(path.join(REPO_ROOT, `.tmp-test-${prefix}-`));
}

export function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

export function writeFile(root: string, relative: string, content: string): string {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content, "utf8");
  return target;
}

export function readAllOutputFiles(dir: string): string {
  const parts: string[] = [];
  const walk = (current: string): void => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) parts.push(fs.readFileSync(abs, "utf8"));
    }
  };
  walk(dir);
  return parts.join("\n");
}

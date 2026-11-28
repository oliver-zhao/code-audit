/**
 * Cleanup of external-tool runs (src/external/cleanup.ts): the process-tree
 * walk and the sweep of stale temporary entries.
 */
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import {
  STALE_TEMP_AGE_MS,
  descendantsOf,
  killProcessTree,
  sweepStaleTempEntries,
} from "../src/external/cleanup.js";
import { cleanup, makeTempDir } from "./helpers.js";

const temp = makeTempDir("cleanup");
afterAll(() => cleanup(temp));

function isAlive(pid: number | undefined): boolean {
  if (pid === undefined) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe("process tree", () => {
  it("orders descendants leaves first", () => {
    const table = new Map<number, number>([
      [10, 1],
      [11, 10],
      [12, 10],
      [13, 11],
      [20, 1],
    ]);
    const order = descendantsOf(10, table);
    expect(order.sort()).toEqual([11, 12, 13]);
    const ordered = descendantsOf(10, table);
    expect(ordered.indexOf(13)).toBeLessThan(ordered.indexOf(11));
    expect(descendantsOf(20, table)).toEqual([]);
  });

  it("kills a child and a grandchild that holds its pipes", async () => {
    const pidFile = path.join(temp, "grandchild.pid");
    const child = spawn(
      process.execPath,
      [
        "-e",
        `const cp=require('child_process');const s=cp.spawn('sleep',['60'],{stdio:['ignore','inherit','inherit']});require('fs').writeFileSync(${JSON.stringify(pidFile)},String(s.pid));setInterval(()=>{},1000);`,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    for (let attempt = 0; attempt < 100 && !fs.existsSync(pidFile); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const grandchild = Number(fs.readFileSync(pidFile, "utf8"));
    expect(isAlive(grandchild)).toBe(true);
    killProcessTree(child);
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(isAlive(child.pid)).toBe(false);
    expect(isAlive(grandchild)).toBe(false);
  });
});

describe("sweep of stale temporary entries", () => {
  it("removes only stale, private entries owned by the user with code-audit's names", () => {
    const dir = path.join(temp, "tmpdir");
    fs.mkdirSync(dir, { recursive: true });
    const old = (Date.now() - STALE_TEMP_AGE_MS - 60_000) / 1000;
    const make = (
      name: string,
      kind: "dir" | "file",
      mode: number,
      stale: boolean,
    ): string => {
      const target = path.join(dir, name);
      if (kind === "dir") {
        fs.mkdirSync(target);
        fs.writeFileSync(path.join(target, "report.json"), "[]");
      } else {
        fs.writeFileSync(target, "[]");
      }
      fs.chmodSync(target, mode);
      if (stale) fs.utimesSync(target, old, old);
      return target;
    };
    const staleHistory = make("code-audit-history-AbC123", "dir", 0o700, true);
    const staleGitleaksDir = make("code-audit-gitleaks-XyZ789", "dir", 0o700, true);
    const staleLegacyReport = make("code-audit-gitleaks-123-456-abcdef.json", "file", 0o600, true);
    const fresh = make("code-audit-history-Fresh1", "dir", 0o700, false);
    const foreignMode = make("code-audit-history-Open22", "dir", 0o755, true);
    const foreignFileMode = make("code-audit-gitleaks-1-2-ab.json", "file", 0o644, true);
    const otherName = make("code-audit-other-Old999", "dir", 0o700, true);
    const lookalike = make("xcode-audit-history-Old999", "dir", 0o700, true);
    // A stale-looking symbolic link to a directory outside: never followed.
    const outside = path.join(temp, "outside-target");
    fs.mkdirSync(outside, { recursive: true });
    fs.chmodSync(outside, 0o700);
    fs.writeFileSync(path.join(outside, "keep.txt"), "keep");
    const link = path.join(dir, "code-audit-history-Link00");
    fs.symlinkSync(outside, link);
    fs.lutimesSync(link, old, old);
    fs.utimesSync(outside, old, old);

    const removed = sweepStaleTempEntries({ dir });
    expect(removed).toBe(3);
    expect(fs.existsSync(staleHistory)).toBe(false);
    expect(fs.existsSync(staleGitleaksDir)).toBe(false);
    expect(fs.existsSync(staleLegacyReport)).toBe(false);
    for (const kept of [fresh, foreignMode, foreignFileMode, otherName, lookalike]) {
      expect(fs.existsSync(kept), kept).toBe(true);
    }
    expect(fs.lstatSync(link).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(path.join(outside, "keep.txt"), "utf8")).toBe("keep");
    // A second sweep finds nothing more.
    expect(sweepStaleTempEntries({ dir })).toBe(0);
  });
});

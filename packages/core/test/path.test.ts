import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { afterAll, describe, expect, it } from "vitest";
import { resolveInside, validateAuditRoot } from "../src/pathJail.js";
import { cleanup, makeTempDir, writeFile } from "./helpers.js";

const root = makeTempDir("jail-root");
const outside = makeTempDir("jail-outside");
writeFile(root, "inside.txt", "inside");
writeFile(outside, "secret.txt", "outside");

afterAll(() => {
  cleanup(root);
  cleanup(outside);
});

describe("path jail", () => {
  it("resolves files inside the root", () => {
    const resolved = resolveInside(root, "inside.txt");
    expect(resolved).toBe(fs.realpathSync(path.join(root, "inside.txt")));
  });

  it("rejects ../ traversal", () => {
    const target = `../${path.basename(outside)}/secret.txt`;
    expect(() => resolveInside(root, target)).toThrow(/escapes the audit root/);
  });

  it("rejects absolute paths outside the root", () => {
    expect(() =>
      resolveInside(root, path.join(outside, "secret.txt")),
    ).toThrow(/escapes the audit root/);
  });

  it("rejects symlinks that escape the root", () => {
    fs.symlinkSync(outside, path.join(root, "escape-dir"));
    expect(() => resolveInside(root, "escape-dir/secret.txt")).toThrow(
      /escapes the audit root/,
    );
    fs.symlinkSync(
      path.join(outside, "secret.txt"),
      path.join(root, "escape-file.txt"),
    );
    expect(() => resolveInside(root, "escape-file.txt")).toThrow(
      /escapes the audit root/,
    );
  });

  it("refuses / and the home directory as audit roots", () => {
    expect(() => validateAuditRoot("/")).toThrow(/filesystem root/);
    expect(() => validateAuditRoot(os.homedir())).toThrow(/home directory/);
  });

  it("allows the root itself and non-existent paths below it", () => {
    expect(resolveInside(root, ".")).toBe(fs.realpathSync(root));
    expect(resolveInside(root, "not-created-yet/report.md")).toContain(
      path.join(fs.realpathSync(root), "not-created-yet"),
    );
  });
});

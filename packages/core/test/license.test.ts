import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import {
  REPO_ROOT,
  cleanup,
  makeTempDir,
  writeFile,
} from "./helpers.js";

const SCRIPT = path.join(REPO_ROOT, "scripts/check-licenses.mjs");
const temp = makeTempDir("licenses");

afterAll(() => cleanup(temp));

describe("production dependency licenses", () => {
  it("reports no GPL/AGPL/LGPL production dependencies in this repository", () => {
    const result = spawnSync(process.execPath, [SCRIPT], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Production dependency licenses");
    expect(result.stdout).toContain(
      "No GPL/AGPL/LGPL production dependencies found.",
    );
  });

  it("fails when a production dependency declares a GPL license", () => {
    const root = path.join(temp, "fake-repo");
    writeFile(
      root,
      "package.json",
      JSON.stringify({ name: "fake", dependencies: { "fake-gpl": "1.0.0" } }),
    );
    writeFile(
      root,
      "node_modules/fake-gpl/package.json",
      JSON.stringify({
        name: "fake-gpl",
        version: "1.0.0",
        license: "GPL-3.0-only",
      }),
    );
    const result = spawnSync(process.execPath, [SCRIPT], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 60_000,
      env: { ...process.env, CODE_AUDIT_LICENSE_ROOT: root },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("fake-gpl");
    expect(result.stderr).toContain("GPL-3.0-only");
  });
});

#!/usr/bin/env node
// Prepare a workspace package for `pnpm pack` / `npm pack` (its `prepack`
// script), and remove what was prepared afterwards (`--clean`, `postpack`).
//
// A published package cannot reach files in the repository root, so the
// files a package needs at run time are copied into it before packing:
//
// - every package: LICENSE and NOTICE;
// - @code-audit/core: `assets/`, which `toolRootDir()` (packages/core/src/meta.ts)
//   uses when the code does not run from a checkout: the rule files, the
//   skill, and the adapter files the installer writes or the inventory
//   recognises.
//
// The copies are git-ignored. In a checkout the originals in the repository
// root are always the ones in use, so a stale copy has no effect.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageDir = process.cwd();
const clean = process.argv.includes("--clean");

/** Files and directories of the repository root that core ships as assets. */
export const CORE_ASSETS = [
  "rules",
  "skills/code-audit/SKILL.md",
  "adapters/opencode/commands/audit.md",
  "adapters/claude-code/commands/audit.md",
  "adapters/claude-code/.claude-plugin/plugin.json",
];
const LEGAL = ["LICENSE", "NOTICE"];

const manifestPath = path.join(packageDir, "package.json");
if (
  path.dirname(packageDir) !== path.join(repoRoot, "packages") ||
  !fs.existsSync(manifestPath)
) {
  process.stderr.write("pack-assets: run from a package directory under packages/\n");
  process.exit(2);
}
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const assetsDir = path.join(packageDir, "assets");

fs.rmSync(assetsDir, { recursive: true, force: true });
for (const name of LEGAL) fs.rmSync(path.join(packageDir, name), { force: true });

if (!clean) {
  for (const name of LEGAL) {
    fs.copyFileSync(path.join(repoRoot, name), path.join(packageDir, name));
  }
  if (manifest.name === "@code-audit/core") {
    for (const relative of CORE_ASSETS) {
      const target = path.join(assetsDir, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.cpSync(path.join(repoRoot, relative), target, { recursive: true });
    }
  }
  if (!fs.existsSync(path.join(packageDir, "dist"))) {
    process.stderr.write("pack-assets: dist/ is missing; run `pnpm build` first\n");
    process.exit(2);
  }
}

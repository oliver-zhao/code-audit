#!/usr/bin/env node
/**
 * Read the declared licenses of production dependencies (not devDependencies)
 * and fail when a GPL/AGPL/LGPL license is found.
 *
 * pnpm stores dependencies as symlinks under each workspace's node_modules, so
 * walking `dependencies` from the workspace manifests also covers transitive
 * production dependencies.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = process.env.CODE_AUDIT_LICENSE_ROOT
  ? path.resolve(process.env.CODE_AUDIT_LICENSE_ROOT)
  : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORKSPACES = [
  "package.json",
  "packages/core/package.json",
  "packages/cli/package.json",
  "packages/mcp/package.json",
];
const FORBIDDEN = /\b(?:A?GPL|LGPL|GPL)(?:-|\b)/i;

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function licenseText(manifest) {
  const license = manifest.license;
  if (typeof license === "string") return license;
  if (license && typeof license === "object" && typeof license.type === "string") {
    return license.type;
  }
  if (Array.isArray(manifest.licenses)) {
    return manifest.licenses
      .map((entry) => (typeof entry === "string" ? entry : entry?.type ?? ""))
      .filter(Boolean)
      .join(" OR ");
  }
  return "UNKNOWN";
}

function resolvePackage(fromDir, name) {
  let current = fromDir;
  for (;;) {
    const candidate = path.join(current, "node_modules", name, "package.json");
    if (fs.existsSync(candidate)) return fs.realpathSync(candidate);
    const parent = path.dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

const seen = new Map();
const queue = [];

for (const relative of WORKSPACES) {
  const manifestPath = path.join(ROOT, relative);
  if (!fs.existsSync(manifestPath)) continue;
  const manifest = readJson(manifestPath);
  for (const name of Object.keys(manifest.dependencies ?? {})) {
    if (name.startsWith("@code-audit/")) continue;
    queue.push({ name, from: path.dirname(manifestPath) });
  }
}

while (queue.length > 0) {
  const { name, from } = queue.shift();
  const manifestPath = resolvePackage(from, name);
  if (!manifestPath) continue;
  const key = fs.realpathSync(manifestPath);
  if (seen.has(key)) continue;
  const manifest = readJson(manifestPath);
  seen.set(key, {
    name: manifest.name ?? name,
    version: manifest.version ?? "unknown",
    license: licenseText(manifest),
  });
  for (const dependency of Object.keys(manifest.dependencies ?? {})) {
    queue.push({ name: dependency, from: path.dirname(manifestPath) });
  }
}

const rows = [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
const violating = rows.filter((row) => FORBIDDEN.test(row.license));

console.log("Production dependency licenses (devDependencies excluded):");
for (const row of rows) {
  console.log(`  ${row.name}@${row.version}  ${row.license}`);
}
console.log(`Checked ${rows.length} production packages.`);
if (violating.length > 0) {
  console.error("Forbidden copyleft licenses found:");
  for (const row of violating) {
    console.error(`  ${row.name}@${row.version}  ${row.license}`);
  }
  process.exit(1);
}
console.log("No GPL/AGPL/LGPL production dependencies found.");

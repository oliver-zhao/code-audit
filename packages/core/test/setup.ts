import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Keep the unit tests hermetic. When real scanners are on PATH (the project's
// `.tools/bin`, a Homebrew `gitleaks`, a distro `semgrep`, ...) the
// fake-executable tests must not accidentally discover and run them, and the
// "tool missing" tests must really see no tool. Drop every PATH directory that
// contains one of the external scanners. The dedicated real-tool test file
// adds `.tools/bin` back explicitly.
//
// A scanner may share its directory with tools the tests do need (`git`,
// `node` in `/usr/bin` or `/opt/homebrew/bin`). Those are re-exposed through a
// private shim directory of symlinks so dropping the directory cannot make
// git-based tests fail or silently skip.
const EXTERNAL_TOOLS = ["opengrep", "semgrep", "osv-scanner", "gitleaks"];
const REQUIRED_TOOLS = ["git", "node"];
const EXECUTABLE_SUFFIXES = process.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""];

function findIn(directory: string, tool: string): string | undefined {
  for (const suffix of EXECUTABLE_SUFFIXES) {
    const candidate = path.join(directory, `${tool}${suffix}`);
    if (fs.existsSync(candidate)) return candidate;
  }
  return undefined;
}

const entries = (process.env.PATH ?? "")
  .split(path.delimiter)
  .filter((entry) => entry.length > 0);
const dropped = entries.filter((entry) =>
  EXTERNAL_TOOLS.some((tool) => findIn(entry, tool) !== undefined),
);
const kept = entries.filter((entry) => !dropped.includes(entry));

const shims: string[] = [];
for (const tool of REQUIRED_TOOLS) {
  if (kept.some((entry) => findIn(entry, tool) !== undefined)) continue;
  for (const entry of dropped) {
    const original = findIn(entry, tool);
    if (!original) continue;
    if (shims.length === 0) {
      shims.push(fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-test-path-")));
    }
    const shimDir = shims[0] as string;
    try {
      fs.symlinkSync(fs.realpathSync(original), path.join(shimDir, path.basename(original)));
    } catch {
      // Symlinks unavailable: fall back to keeping the original directory.
      kept.push(entry);
    }
    break;
  }
}
process.env.PATH = [...kept, ...shims].join(path.delimiter);

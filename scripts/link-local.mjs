#!/usr/bin/env node
// Create the ./bin wrappers that point at the built dist files.
//
// The wrappers are committed to the repository and contain no absolute paths:
// each one resolves the repository root relative to its own location. This
// script (re)writes them and marks them executable so `pnpm run link:local`
// is enough to put `code-audit` and `code-audit-mcp` on PATH via ./bin.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const binDir = path.join(repoRoot, "bin");

const wrappers = {
  "code-audit": `#!/usr/bin/env sh
# code-audit CLI wrapper. Resolve the repo root relative to this script so the
# wrapper works from any directory and contains no absolute paths.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec node "$SCRIPT_DIR/../packages/cli/dist/index.js" "$@"
`,
  "code-audit-mcp": `#!/usr/bin/env sh
# code-audit MCP server wrapper (stdio). No absolute paths.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec node "$SCRIPT_DIR/../packages/mcp/dist/bin.js" "$@"
`,
};

fs.mkdirSync(binDir, { recursive: true });
for (const [name, content] of Object.entries(wrappers)) {
  const target = path.join(binDir, name);
  fs.writeFileSync(target, content, "utf8");
  fs.chmodSync(target, 0o755);
  process.stdout.write(`linked ${path.relative(repoRoot, target)}\n`);
}

const cliDist = path.join(repoRoot, "packages/cli/dist/index.js");
const mcpDist = path.join(repoRoot, "packages/mcp/dist/bin.js");
for (const dist of [cliDist, mcpDist]) {
  if (!fs.existsSync(dist)) {
    process.stderr.write(
      `warning: ${path.relative(repoRoot, dist)} is missing; run pnpm build first\n`,
    );
  }
}
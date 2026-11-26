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
  "code-audit": `#!/bin/sh
# code-audit CLI wrapper. Resolve the repo root relative to this script so the
# wrapper works from any directory and contains no absolute paths.
set -eu
# Follow symlinks so the wrapper also works when it is linked into a PATH
# directory (ln -s .../bin/code-audit ~/.local/bin/). Plain POSIX sh: \`readlink -f\`
# and \`realpath\` are not available on every macOS/BSD release.
SELF=\$0
HOPS=0
while [ -L "\$SELF" ]; do
  HOPS=\$((HOPS + 1))
  if [ "\$HOPS" -gt 40 ]; then
    echo "code-audit: too many levels of symbolic links: \$0" >&2
    exit 2
  fi
  LINK=\$(readlink "\$SELF")
  case \$LINK in
    /*) SELF=\$LINK ;;
    *) SELF=\$(dirname -- "\$SELF")/\$LINK ;;
  esac
done
SCRIPT_DIR=\$(CDPATH= cd -- "\$(dirname -- "\$SELF")" && pwd -P)
exec node "\$SCRIPT_DIR/../packages/cli/dist/index.js" "\$@"
`,
  "code-audit-mcp": `#!/bin/sh
# code-audit MCP server wrapper (stdio). No absolute paths.
set -eu
# Follow symlinks so the wrapper also works when it is linked into a PATH
# directory (ln -s .../bin/code-audit-mcp ~/.local/bin/). Plain POSIX sh: \`readlink -f\`
# and \`realpath\` are not available on every macOS/BSD release.
SELF=\$0
HOPS=0
while [ -L "\$SELF" ]; do
  HOPS=\$((HOPS + 1))
  if [ "\$HOPS" -gt 40 ]; then
    echo "code-audit: too many levels of symbolic links: \$0" >&2
    exit 2
  fi
  LINK=\$(readlink "\$SELF")
  case \$LINK in
    /*) SELF=\$LINK ;;
    *) SELF=\$(dirname -- "\$SELF")/\$LINK ;;
  esac
done
SCRIPT_DIR=\$(CDPATH= cd -- "\$(dirname -- "\$SELF")" && pwd -P)
exec node "\$SCRIPT_DIR/../packages/mcp/dist/bin.js" "\$@"
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
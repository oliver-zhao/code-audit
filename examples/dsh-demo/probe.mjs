// Live DSH MCP probe for code-audit.
//
// This uses the real `@deepseek-ai/dsh-mcp-client` probeServer API that ships
// with DSH to connect to `code-audit-mcp` and list its advertised tools. It does
// not start an LLM session and does not modify any DSH profile.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

function findDshPackageRoot() {
  try {
    const resolved = execFileSync("sh", ["-c", "command -v dsh"], {
      encoding: "utf8",
    }).trim();
    if (resolved) {
      const real = fs.realpathSync(resolved);
      // <root>/lib/bin.js -> <root>
      return path.dirname(path.dirname(real));
    }
  } catch {
    // fall through
  }
  try {
    const globalRoot = execFileSync("npm", ["root", "-g"], {
      encoding: "utf8",
    }).trim();
    return path.join(globalRoot, "@deepseek-ai/dsh");
  } catch {
    return undefined;
  }
}

const dshRoot = findDshPackageRoot();
if (!dshRoot) {
  console.error("cannot locate the DSH installation; install DSH first");
  process.exit(2);
}
const clientEntry = path.join(
  dshRoot,
  "node_modules/@deepseek-ai/dsh-mcp-client/lib/index.js",
);
if (!fs.existsSync(clientEntry)) {
  console.error(`cannot locate dsh-mcp-client at ${clientEntry}`);
  process.exit(2);
}

const { probeServer } = await import(pathToFileURL(clientEntry).href);

const config = {
  transport: "stdio",
  serverName: "code-audit",
  command: "code-audit-mcp",
  args: [],
  env: {},
  cwd: process.cwd(),
  toolCallTimeoutMs: 10000,
  closeTimeoutMs: 5000,
  expandTemplates: false,
  failOnStartupError: false,
};

const result = await probeServer({}, config, { timeoutMs: 15000 });
if (!result.ok) {
  console.error(`probe failed at ${result.stage}: ${result.message}`);
  process.exit(1);
}
console.log(
  JSON.stringify(
    {
      server: result.serverInfo,
      toolCount: result.toolNames.length,
      tools: result.toolNames,
      truncated: result.truncated,
      durationMs: result.durationMs,
    },
    null,
    2,
  ),
);

# code-audit

`code-audit` is a deterministic source-code security auditor. It scans a local
project, produces candidate findings with evidence, and gives a host agent (or a
human) the tools to review them and render a report. The core never calls an LLM:
**you** are the reviewer. All repository content is treated as untrusted data.

The project ships three layers:

- **Core** (`@code-audit/core`) — inventory, built-in rule engine, built-in secret
  detection, lockfile parsing with OSV.dev queries, finding model, dedupe,
  verdict storage and Markdown/JSON/SARIF reports.
- **CLI** (`code-audit`) — `scan`, `status`, `findings`, `read`, `search`,
  `verdict`, `add-finding`, `report`, `install`, `doctor`, `mcp`.
- **MCP server** (`code-audit-mcp`) — the same workflow exposed as `audit_*`
  tools over stdio for agent hosts.

## Quick start

```sh
pnpm install
pnpm build
pnpm run link:local          # creates ./bin/code-audit and ./bin/code-audit-mcp
export PATH="$PWD/bin:$PATH" # or add ./bin to your PATH permanently

code-audit scan <dir>                 # scan a project (writes <dir>/.audit/<run>)
code-audit scan <dir> --offline       # skip OSV.dev network queries
code-audit install --host opencode    # install the agent adapter files
code-audit doctor                     # show Node, rules and external tool status
```

`code-audit-mcp` is the stdio MCP server; point your host at it (the `install`
command writes the right config for each supported host).

## Engine tiers

The tool is designed so that a scan always succeeds with **zero external
dependencies**, and gets stronger when optional scanners are present.

| Tier | Engines | Dependency | Notes |
|---|---|---|---|
| **Tier 0** (always available) | built-in YAML rules, built-in secret detection, lockfile parsing + OSV.dev batch query | Node only | OSV queries send only package name/version; `--offline` skips them and the report says so. |
| **Tier 1** (auto when found) | Opengrep/Semgrep, OSV-Scanner, Gitleaks | present on `PATH` | Results are merged and deduped with Tier 0. A missing, failing or timing-out tool never fails the scan; it is recorded as a warning. |
| **Tier 2** (explicit, future) | govulncheck, Bandit, gosec, SpotBugs, Roslyn, clang-tidy | language toolchains | Not implemented yet. |

Use `--engines builtin,opengrep,osv-scanner,gitleaks` to select engines
explicitly, or `--no-external` for Tier 0 only. Opengrep is preferred over
Semgrep; Semgrep is used only when Opengrep is not installed.

## Host support

| Host | Adapter | Verification status |
|---|---|---|
| OpenCode | `.opencode/` + `opencode.json` | Verified on a real host (OpenCode v2.4.1). |
| DSH | `dsh/cordis.patch.yml` + `.dsh/` | Verified on a real host (DSH 0.2.2-rc.5). |
| Claude Code | `.claude-plugin/`, `.mcp.json`, `skills/`, `commands/` | Format/schema checked only — **not verified on a real host**. |
| Codex | `.codex/config.toml`, `.agents/`, `AGENTS.md` | Format/schema checked only — **not verified on a real host**. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed and no finding reached the `--fail-on` / `--min-confidence` thresholds. |
| `1` | At least one finding reached the thresholds (or Node < 22 for `doctor`). |
| `2` | Runtime error (bad arguments, missing path, rule loading failure, ...). |

## License

Apache-2.0. The repository bundles only self-written rules; no Semgrep
registry rules are distributed.
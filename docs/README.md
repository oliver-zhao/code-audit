# Documentation index

## User documentation

Current for this version of the code.

| Document | Content |
|---|---|
| [../README.md](../README.md) | What the tool is, quick start, engines, hosts, CI, configuration reference, limits. |
| [reports.md](reports.md) | Files of a run, the counting model, report layout, confidence adjustments. |
| [rules.md](rules.md) | How built-in rules work, the rule file schema, adding a rule, the finding / hotspot policy. |
| [mcp.md](mcp.md) | The MCP server: tools, arguments, result shapes. |
| [security-model.md](security-model.md) | Threat model, guarantees and non-guarantees, repository-controlled mechanisms. |
| [github-action.md](github-action.md) | The GitHub Action: inputs, outputs, diff mode, permissions, fork pull requests, comments, threat model. |
| [../CHANGELOG.md](../CHANGELOG.md) | Changes per release. |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Development setup, tests, rule contributions. |
| [../SECURITY.md](../SECURITY.md) | Reporting a vulnerability. |
| `../adapters/<host>/README.md` | Per-host installation details and verification status. |

## Results and known limits

What changed in release 0.3.0, and its known limits, is in
[../CHANGELOG.md](../CHANGELOG.md) and the "Limits" section of the
[README](../README.md#limits). The two reports below come from earlier
development stages (before 0.3.0). They record measured results on public
repositories and the known limits at that time; their rule counts and
results predate the 0.3.0 rule expansion.

| Document | Content |
|---|---|
| [M4_REPORT.md](M4_REPORT.md) | Real-project results, report layout, host adapters, trust hardening; verification and known limits. |
| [PY1_REPORT.md](PY1_REPORT.md) | Python support: rules, taint rules, dependency parsers; results on public Python projects; known limits. |

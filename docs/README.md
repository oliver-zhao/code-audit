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
| [../CHANGELOG.md](../CHANGELOG.md) | Changes per release. |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Development setup, tests, rule contributions. |
| [../SECURITY.md](../SECURITY.md) | Reporting a vulnerability. |
| `../adapters/<host>/README.md` | Per-host installation details and verification status. |

## Results and known limits

Reports of the two most recent development stages. They are the reference
for measured results on public repositories and for the list of known limits.

| Document | Content |
|---|---|
| [M4_REPORT.md](M4_REPORT.md) | Real-project results, report layout, host adapters, trust hardening; verification and known limits. |
| [PY1_REPORT.md](PY1_REPORT.md) | Python support: rules, taint rules, dependency parsers; results on public Python projects; known limits. |

## Historical development records

**These documents are kept as a record of how the project was built. They
were written during development, several of them in Chinese, and are not
maintained: commands, paths, flags, counts and file layouts in them may be
out of date.** Do not use them as documentation of the current behaviour;
use the documents above.

| Document | Language | What it is |
|---|---|---|
| [../AUDIT_AGENT_PLAN.md](../AUDIT_AGENT_PLAN.md) | Chinese | The original project plan. |
| [PLAN_SUPPLEMENT.md](PLAN_SUPPLEMENT.md) | Chinese | Supplement to the plan. |
| [M0_REPORT.md](M0_REPORT.md) | Chinese | Stage report M0: runnable skeleton (core, CLI, fixtures, tests). |
| [M1_REPORT.md](M1_REPORT.md) | Chinese | Stage report M1: MCP server and host adapters. |
| [M2_REPORT.md](M2_REPORT.md) | English | Stage report M2: external scanner adapters and `doctor`. |
| [M3_REPORT.md](M3_REPORT.md) | English | Stage report M3: baseline, ignore file, incremental scans, CI. |
| `../tasks/M0.md`, `M0.1.md`, `M1.md` | Chinese | Task briefs given to the implementers of stages M0 and M1. |
| `../tasks/M2.md`, `M2.1.md`, `M3.md`, `M3.1.md`, `PY1.md` | English | Task briefs of the later stages. |

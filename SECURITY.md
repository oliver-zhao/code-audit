# Security policy

## Reporting a vulnerability

Please report vulnerabilities in code-audit **privately** through GitHub
security advisories:

1. Open <https://github.com/oliver-zhao/code-audit/security/advisories/new>
   (repository **Security** tab, **Report a vulnerability**).
2. Describe the problem, the affected version (`code-audit --version`) and
   the platform, and attach the smallest input that shows it: a few files, the
   command line, and what happened against what you expected.

Do not open a public issue or pull request for a vulnerability, and do not
include real credentials in a report. You will get an answer in the advisory
thread. There is no bug bounty.

## What counts as a vulnerability

code-audit reads repositories that may be hostile; its threat model and
guarantees are in [docs/security-model.md](docs/security-model.md). A report
is a vulnerability when an audited repository (or MCP client input) can make
the tool break one of those guarantees, for example:

- execute code, or read or write files outside the audit root and the run
  directory;
- hide a finding, lower a result or keep files away from the scan **without**
  the corresponding `WARNING`, or while `--untrusted` is set;
- get a detected secret written in clear text to a report, the terminal, CI
  annotations or MCP output;
- inject structure (headings, tables, links, control characters) into a
  report or summary;
- make `code-audit install` write outside the project, follow a symbolic
  link, or write an MCP command taken from a file in the project;
- hang or crash the scan with a small input (regular-expression or parser
  blow-up).

Not vulnerabilities (please use the issue templates instead): a rule that
misses a vulnerable pattern (false negative), a rule that reports safe code
(false positive), and the documented limits in the README and in
`docs/security-model.md` ("What it does not guarantee").

## Supported versions

Only the latest release receives fixes. The project is pre-1.0.

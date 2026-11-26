# Contributing

Thanks for helping. This file covers the setup, the tests, and the rules for
contributing detection rules. Vulnerabilities in the tool itself go through
[SECURITY.md](SECURITY.md), not through issues or pull requests.

## Setup

Requirements: Node.js 22 or later, pnpm (`corepack enable` uses the version
pinned in `package.json`), git.

```sh
git clone https://github.com/oliver-zhao/code-audit.git
cd code-audit
corepack enable
pnpm install
pnpm build
./bin/code-audit doctor
```

Layout: `packages/core` (engine), `packages/mcp` (MCP server), `packages/cli`
(command line), `rules/` (rule files), `fixtures/vulnerable` and
`fixtures/clean` (samples the tests scan), `skills/` and `adapters/` (what
`code-audit install` writes), `docs/` (see `docs/README.md`).

## Checks

All three must pass before a pull request; CI runs the same commands on
Linux and macOS with Node 22 and 24.

```sh
pnpm build
pnpm test                  # builds, then runs vitest
pnpm run check:licenses    # no (A/L)GPL production dependency
```

Notes on the tests:

- They are hermetic: `packages/core/test/setup.ts` removes every `PATH`
  directory that contains `opengrep`, `semgrep`, `osv-scanner` or `gitleaks`,
  so scanners installed on your machine do not change the outcome.
- They create and remove `.tmp-test-*` directories in the repository root.
- The CLI tests run the built CLI (`packages/cli/dist`), which is why
  `pnpm test` builds first.
- Windows is untested.

### Tests with the real external scanners

`packages/core/test/realtools.test.ts` runs Opengrep, OSV-Scanner and
Gitleaks for real. It looks for the three binaries in a project-local
`.tools/bin` directory (git-ignored) and is skipped unless all three are
there. Nothing is downloaded by the test suite; put the binaries there
yourself, from the projects' release pages:

```sh
mkdir -p .tools/bin
# copy or symlink the three executables:
#   .tools/bin/opengrep      (tested with 1.33.1)
#   .tools/bin/osv-scanner   (tested with 2.7.1)
#   .tools/bin/gitleaks      (tested with 8.30.1)
pnpm test
```

Run these when you change `rules/opengrep/`, `packages/core/src/external/` or
the merge and de-duplication code. The OSV-Scanner test needs network access.

### Packaging

`pnpm run pack:verify` packs the three packages, checks the tarball contents,
installs them into a temporary directory and runs the installed `code-audit`
and `code-audit-mcp`. Run it when you change `package.json` files, the
`files` lists, `scripts/pack-assets.mjs`, or how rules, skills and adapter
files are located (`toolRootDir()` in `packages/core/src/meta.ts`).

## Contributing rules

How rules work and the schema are in [docs/rules.md](docs/rules.md). The
requirements for a rule contribution:

1. **Original rules only.** Write the rule yourself. Do not copy, port or
   translate rules from the Semgrep registry, other scanners' rule packs or
   any source whose licence is not compatible with Apache-2.0. Citing a CWE
   or a public advisory as the reason for a rule is fine; copying another
   project's pattern is not. By opening a pull request you state that the
   contribution is your own work and that you license it under Apache-2.0.
2. **A seed and a clean counterpart.** Every rule needs at least one seed in
   `fixtures/vulnerable/` with an entry in `fixtures/vulnerable/EXPECTED.json`
   (file, line, rule id, language, kind), and the safe way to write the same
   code in `fixtures/clean/`. The clean tree must stay free of findings.
3. **The finding / hotspot policy.** A `finding` at medium or high confidence
   must be justified by the matched statement itself; a bare dangerous API
   call is a `hotspot`. See "Findings and hotspots" in `docs/rules.md`.
4. **Bounded patterns.** Rules are run against pathological input by the
   tests; a slow pattern fails the build.
5. **No real secrets.** Fixture credentials must be fake, and a rule that
   matches a credential literal must set `redactEvidence: true`.
6. **Measure on real code when you can.** A rule that fires many times on a
   well-maintained public project is probably a hotspot, not a finding. Scan
   only; never execute the code of a project you scan.

## Do not weaken tests

A pull request must not make a failing test pass by loosening it: no deleted
or skipped tests, no removed seeds or clean counterparts, no relaxed
assertions, no raised time limits, unless the pull request explains why the
old expectation was wrong. This applies in particular to the trust and
redaction tests (`trust`, `runtrust`, `untrusted`, `seams`, `review2`,
`path`), which encode attacks that were found in review. If a change makes
one of them fail, fix the change.

## Other conventions

- No new runtime dependencies without discussion; the engine depends on
  `yaml` and `zod`, the MCP server additionally on the MCP SDK.
- `skills/code-audit/SKILL.md` is the canonical skill. The copies under
  `adapters/*/` must be byte-identical (tested); edit the canonical file and
  copy it.
- User-visible changes get a line in [CHANGELOG.md](CHANGELOG.md) under
  "Unreleased", and documentation in the README or `docs/`. A test compares
  `code-audit --help`, the README and the docs with the implemented flags,
  rule fields and MCP tools.
- The version lives in the four `package.json` files, `TOOL_VERSION`
  (`packages/core/src/meta.ts`), the Claude Code plugin manifest and the
  marketplace manifest; a test checks that they agree.
- Text from an audited repository is untrusted wherever it ends up. New
  output paths must go through the existing escaping (`report.ts`) and
  redaction (`redact.ts`) helpers, and new file writes through `safeFs.ts`.

## Reporting bugs, false positives and false negatives

Use the issue templates. Each asks for a minimal sample and the output of
`code-audit doctor`, because results depend on the version, the rule set and
which external scanners are installed.

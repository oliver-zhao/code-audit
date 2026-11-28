# GitHub Action

code-audit ships a composite GitHub Action (`action.yml` at the repository
root) and a second, small Action for pull request comments
(`comment/action.yml`). Together they give:

- a scan of every pull request, limited to the lines the pull request adds
  or changes (`--since <merge-base> --diff-lines`), or a full scan;
- SARIF uploaded to GitHub code scanning;
- inline review comments on the changed lines plus one summary comment,
  posted by a separate workflow that never runs pull request code.

code-audit is not published to npm yet: the Action builds the CLI from its
own source (`pnpm install --frozen-lockfile && pnpm build` in a copy under
`$RUNNER_TEMP`) and runs it with Node 22. Nothing of the scanned repository
is installed, built or executed.

## Quick start

Copy the two example workflows and replace `OWNER/code-audit@<sha>` with the
repository and the full commit SHA of the release you use:

- [`examples/workflows/code-audit-pr.yml`](../examples/workflows/code-audit-pr.yml)
  - stage 1, `on: pull_request`: checkout of the head commit with
  `fetch-depth: 0`, then the scan.
- [`examples/workflows/code-audit-comment.yml`](../examples/workflows/code-audit-comment.yml)
  - stage 2, `on: workflow_run` of stage 1: posts the comments.

The `workflows:` list in stage 2 must contain the `name:` of stage 1.

```yaml
- uses: actions/checkout@<sha> # vX.Y.Z
  with:
    ref: ${{ github.event.pull_request.head.sha }}
    fetch-depth: 0
    persist-credentials: false
- uses: OWNER/code-audit@<sha> # vX.Y.Z
  with:
    fail-on: high
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan, relative to the workspace (must stay inside it; no `..` and no symbolic link on the way). Finding paths in comments and SARIF are made relative to the repository root. |
| `fail-on` | `high` | Lowest severity that fails the step: `info`, `low`, `medium`, `high`, `critical`. |
| `min-confidence` | `medium` | Lowest confidence that counts: `low`, `medium`, `high`. |
| `mode` | `diff` on `pull_request`, else `full` | `diff`: only findings on lines the pull request adds or changes. `full`: the whole tree. |
| `baseline` | empty | Path of a baseline file in the repository; read from the trusted commit (below). |
| `engines` | `builtin` | Comma-separated engines. External engines (opengrep, semgrep, osv-scanner, gitleaks) must already be installed on the runner. |
| `offline` | `false` | `true`: no OSV.dev queries (dependencies are listed, not checked). |
| `upload-sarif` | `true` | Upload `results.sarif` to code scanning (category `code-audit`). |
| `comment` | `true` | Upload the artifact for the comment workflow (pull request events only). |
| `artifact-name` | `code-audit-results` | Name of that artifact (use different names in a matrix). |
| `version` | empty | Empty: the version of this Action. Any other value must equal it, otherwise the step fails (pick the Action ref of that release instead). |

## Outputs

| Output | Meaning |
|---|---|
| `findings-count` | Findings at or above `min-confidence` after the diff filter (the headline number of the report). |
| `new-findings-count` | Findings not in the baseline; equal to `findings-count` without one. |
| `sarif-file` | Path of the SARIF report uploaded to code scanning (`results-repo.sarif`: paths relative to the repository root). |
| `exit-code` | `0` clean, `1` findings reached `fail-on`, `2` the scan could not complete. |

The step fails with the scan's exit code after SARIF and the artifact are
uploaded, so the comment workflow also runs when findings fail the check.
Annotations (`--ci`) and the job summary are written as well.

## What the scan does

Every scan runs `code-audit scan <path> --untrusted --ci`: nothing in the
checked-out code can lower the result (no ignore file or baseline of the
pull request, no inline `code-audit:ignore` comments, no confidence lowering
for test or example paths, default-excluded directories are read).

**Ignore file and baseline.** They are read from a commit the change under
test cannot modify:

| Event | Trusted commit |
|---|---|
| `pull_request` | `github.event.pull_request.base.sha` (the base branch) |
| `push` and others | `github.sha` (already in the repository) |

The Action copies `<path>/.code-audit-ignore` and the `baseline` input from
that commit with `git cat-file blob` (no filter or textconv) to
`$RUNNER_TEMP` and passes them as `--ignore-file` / `--baseline`. The CLI
applies such files under `--untrusted` only because they are absolute paths
outside the scanned directory and its git work tree, and names each applied
file in a warning. A pull request that edits
`.code-audit-ignore` therefore changes nothing for its own scan; the edit
takes effect once it is merged. These git commands run in the Action's
shell on the checkout created by `actions/checkout`, whose `.git/config` is
written by the checkout, not by the pull request.

**Diff mode.** The comparison point is `git merge-base <base sha> HEAD`, the
same as GitHub's pull request diff, so changes on the base branch since the
branch point are not attributed to the pull request. Check out the head
commit (`ref: ${{ github.event.pull_request.head.sha }}`) with
`fetch-depth: 0`; with the default merge-commit checkout the scan still
works, but inline comment positions can be off where the base branch changed
the same file (the Action prints a notice). Without the history the Action
fails and asks for `fetch-depth: 0`.

`--diff-lines` keeps a finding when its line range touches an added or
changed line (Myers line diff against the blob of the merge base; a change
of line endings alone does not count). Dependency advisories and secrets are
kept for the whole changed file. When a pull request only deletes lines
(a guard or sanitizer, say), the new lines on either side of the deletion
count as changed. A file whose old or new text contains line breaks the
engines number differently (a lone CR, U+2028, U+2029, U+0085, `\v`, `\f`)
counts as changed in full; external engines such as Opengrep number lines
themselves, so this keeps their findings in scope too. Files over 20,000 lines or with more than
5,000 changed lines count as changed in full (a warning names them). The
number of results left out is `scope.diffLinesFiltered` in `run.json` and
`findings.json`, and is printed in the summary.

## Permissions

| Workflow | Trigger | Permissions | Runs PR code? |
|---|---|---|---|
| stage 1 (`code-audit-pr.yml`) | `pull_request` | `contents: read`, `security-events: write` | The scanner reads it as text; nothing of the PR is executed. |
| stage 2 (`code-audit-comment.yml`) | `workflow_run` | `pull-requests: write`, `actions: read` | No: no checkout; only the comment Action's own `comment.mjs`. |

Do not use `pull_request_target` for the scan: it runs with a write token and
the repository's secrets. The Action prints a warning when it sees it.

## Pull requests from forks

- Stage 1 runs with a read-only token and no secrets. The SARIF upload fails
  there; the step is `continue-on-error` and the Action prints a notice. The
  SARIF is still in the artifact and the results are in the job summary.
- Stage 2 runs from the default branch's copy of the workflow (a pull
  request cannot change it) with write access to pull request comments.
- For a fork GitHub leaves `workflow_run.pull_requests` empty. The comment
  script then looks up the open pull request whose head repository, branch
  and head commit equal those of the triggering run, and uses it only if the
  artifact names the same number.
- Depending on the repository settings, workflows of first-time
  contributors wait for approval.

## Comments

`comment/action.yml` downloads the artifact of the triggering run
(`actions/download-artifact` with `run-id`) and runs
`scripts/action/comment.mjs` (Node, no dependencies):

1. `comment-data.json` is size-capped (2 MiB), must be a regular file and is
   validated field by field (schema version, commit ids, numbers, enums,
   fingerprints `^[0-9a-f]{64}$`, rule ids, string lengths, at most 200
   findings, no duplicate fingerprints). Any error rejects the whole file.
2. The pull request number in it must be one GitHub associates with the
   triggering run (see forks above), and its head commit must equal
   `workflow_run.head_sha`. Otherwise nothing is posted.
3. Inline comments are placed only on lines of the pull request's diff
   (right side, from `GET /pulls/{n}/files`), at most 20 per run
   (`max-inline`, at most 50). Each starts with
   `<!-- code-audit:<fingerprint> -->`; a later run updates that comment
   instead of adding one. Everything else goes into one summary comment
   (`<!-- code-audit:summary -->`), also updated in place. Only comments
   written by `github-actions[bot]` are updated.
4. Bodies are a fixed template. Text from the repository (titles, file
   names, evidence) appears only inside code spans or fenced code blocks;
   backticks are replaced by a look-alike so the code cannot be closed,
   every `@` is followed by a zero-width space so nobody is mentioned,
   control, zero-width and bidirectional characters are removed, and each
   field is capped in length. Markdown links, HTML and headings in the text
   are therefore shown, not rendered.

Inline comments for findings that are no longer reported are not deleted.

## Threat model

| Attacker | Can | Cannot |
|---|---|---|
| Author of a pull request (fork or branch) | Change any file of the PR, including stage 1's workflow file and the scanned code; make stage 1 upload any artifact. | Change stage 2 (it runs from the default branch); make stage 2 run their code; post to another pull request or for another commit (number and head commit checks); add Markdown, links or mentions to comments; suppress findings with `.code-audit-ignore`, a baseline or inline comments of the PR (`--untrusted`, trusted-commit copies). |
| Same, through the scanned content | Make the scanner see crafted files, `.gitattributes` and `.git/config` content committed in the PR. | Run programs through git: the scanner's git calls are hardened (see `docs/security-model.md`), and the Action's own git calls read the checkout's config. |
| Upstream of a third-party action | - | Swap the code: every action is pinned to a full commit SHA. |

Limits, by design:

- `uses: ./` (as in this repository's `.github/workflows/code-audit.yml`)
  runs the Action of the checked-out commit, so a pull request can change
  the scanner it is checked with. Other repositories should pin a release
  commit.
- A pull request can make stage 1 report fewer findings by changing stage
  1's workflow (for example removing the scan step); the comment stage then
  posts what the artifact says, or nothing. Use branch protection with a
  required check from a workflow the pull request cannot alter if the scan
  must be a gate.
- `pnpm install --frozen-lockfile` of the Action's own source downloads its
  dependencies from the npm registry at the versions in `pnpm-lock.yaml`.

## This repository

`.github/workflows/code-audit.yml` scans this repository with `uses: ./`:
same-repository pull requests in diff mode and pushes to `master` in full
mode, with SARIF upload and without comments. The committed
`.code-audit-ignore` (read from the base or pushed commit) suppresses the
fixtures and test inputs.

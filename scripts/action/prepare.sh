#!/usr/bin/env bash
# Step "Check inputs" of the code-audit Action (action.yml).
#
# Validates every input (they arrive as environment variables, never as
# text expanded into this script), decides the mode, copies the Action's
# source to $RUNNER_TEMP so the build never writes into the scanned
# workspace, and reads the ignore file and the baseline from a commit the
# pull request cannot change. Writes step outputs to $GITHUB_OUTPUT.
set -euo pipefail

fail() {
  echo "::error::code-audit: $*"
  exit 2
}

out() {
  # Values are validated before they get here; a newline would still start
  # a new output, so refuse it.
  case "$2" in *$'\n'*|*$'\r'*) fail "internal error: output $1 contains a line break" ;; esac
  echo "$1=$2" >> "$GITHUB_OUTPUT"
}

: "${GITHUB_WORKSPACE:?}" "${RUNNER_TEMP:?}" "${GITHUB_OUTPUT:?}" "${ACTION_PATH:?}"

# ---- plain inputs -----------------------------------------------------------
case "$INPUT_FAIL_ON" in info|low|medium|high|critical) ;; *) fail "fail-on must be info, low, medium, high or critical" ;; esac
case "$INPUT_MIN_CONFIDENCE" in low|medium|high) ;; *) fail "min-confidence must be low, medium or high" ;; esac
case "$INPUT_OFFLINE" in true|false) ;; *) fail "offline must be true or false" ;; esac
case "$INPUT_UPLOAD_SARIF" in true|false) ;; *) fail "upload-sarif must be true or false" ;; esac
case "$INPUT_COMMENT" in true|false) ;; *) fail "comment must be true or false" ;; esac
if ! [[ "$INPUT_ENGINES" =~ ^[a-z-]+(,[a-z-]+)*$ ]]; then fail "engines must be a comma-separated list of engine names"; fi
if ! [[ "$INPUT_ARTIFACT_NAME" =~ ^[A-Za-z0-9._-]{1,100}$ ]]; then fail "artifact-name may contain letters, digits, '.', '_' and '-' only"; fi
if [ -n "$INPUT_VERSION" ] && ! [[ "$INPUT_VERSION" =~ ^[0-9A-Za-z.+-]{1,40}$ ]]; then fail "version is not a version number"; fi

is_pr=false
case "$EVENT_NAME" in pull_request|pull_request_target) is_pr=true ;; esac
if [ "$EVENT_NAME" = "pull_request_target" ]; then
  echo "::warning::code-audit: pull_request_target runs with a write token and secrets; use pull_request for the scan and the separate comment workflow (docs/github-action.md)"
fi

mode="$INPUT_MODE"
if [ -z "$mode" ]; then
  if [ "$is_pr" = true ]; then mode=diff; else mode=full; fi
fi
case "$mode" in diff|full) ;; *) fail "mode must be diff or full" ;; esac
if [ "$mode" = diff ] && [ "$is_pr" != true ]; then
  fail "mode diff needs a pull_request event (there is no base commit to compare with)"
fi

sha_re='^([0-9a-f]{40}|[0-9a-f]{64})$'
base_sha=""
head_sha=""
pr_number=""
if [ "$is_pr" = true ]; then
  [[ "$PR_BASE_SHA" =~ $sha_re ]] || fail "the pull request event has no base commit"
  [[ "$PR_HEAD_SHA" =~ $sha_re ]] || fail "the pull request event has no head commit"
  [[ "$PR_NUMBER" =~ ^[1-9][0-9]{0,9}$ ]] || fail "the pull request event has no number"
  head_sha="$PR_HEAD_SHA"
  pr_number="$PR_NUMBER"
fi

# ---- scan target: inside the workspace --------------------------------------
case "$INPUT_PATH" in /*) fail "path must be relative to the workspace" ;; esac
workspace="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
# Neither the directory nor any directory on the way to it may be a symbolic
# link (a pull request could replace one to point the scan, and the choice of
# the base commit's ignore file, somewhere else), and no ".." component.
walk="$workspace"
IFS='/' read -r -a components <<< "$INPUT_PATH"
for component in "${components[@]}"; do
  case "$component" in
    ""|.) continue ;;
    ..) fail "path must not contain '..'" ;;
  esac
  walk="$walk/$component"
  if [ -L "$walk" ]; then fail "path must not be or pass through a symbolic link: $INPUT_PATH"; fi
done
target="$(cd "$GITHUB_WORKSPACE" && cd -- "$INPUT_PATH" 2>/dev/null && pwd -P)" || fail "path does not exist: $INPUT_PATH"
case "$target/" in "$workspace"/*) ;; *) fail "path must stay inside the workspace" ;; esac

# git in the checked-out repository: its configuration was written by the
# checkout, not by the pull request; these overrides are kept anyway.
g() {
  git -C "$target" -c core.fsmonitor=false -c core.hooksPath=/dev/null \
    -c core.pager=cat -c diff.external= -c core.attributesFile=/dev/null \
    --no-pager "$@"
}

have_commit() { g cat-file -e "$1^{commit}" 2>/dev/null; }

# The commit the ignore file and the baseline are read from: one the change
# under test cannot modify (base of a pull request), else the pushed commit.
trusted_ref=""
if [ "$is_pr" = true ]; then
  trusted_ref="$PR_BASE_SHA"
elif [[ "${GITHUB_SHA:-}" =~ $sha_re ]]; then
  trusted_ref="$GITHUB_SHA"
fi

if [ -n "$trusted_ref" ] && ! have_commit "$trusted_ref"; then
  g fetch --no-tags --quiet origin "$trusted_ref" 2>/dev/null || true
fi
if [ -n "$trusted_ref" ] && ! have_commit "$trusted_ref"; then
  if [ "$mode" = diff ]; then
    fail "commit $trusted_ref is not in the checkout; use actions/checkout with fetch-depth: 0"
  fi
  echo "::warning::code-audit: commit $trusted_ref is not in the checkout; no ignore file or baseline is used"
  trusted_ref=""
fi

since=""
if [ "$mode" = diff ]; then
  # Compare with the merge base, as GitHub's pull request diff does: lines
  # changed on the base branch since the branch point are not the PR's.
  since="$(g merge-base "$PR_BASE_SHA" HEAD 2>/dev/null)" \
    || fail "no merge base of $PR_BASE_SHA and HEAD; use actions/checkout with fetch-depth: 0"
  [[ "$since" =~ $sha_re ]] || fail "unexpected merge-base output"
  checked_out="$(g rev-parse HEAD)"
  if [ "$checked_out" != "$PR_HEAD_SHA" ]; then
    echo "::notice::code-audit: the checkout is not the pull request head ($PR_HEAD_SHA); inline comment positions follow the head commit, so check out ref: github.event.pull_request.head.sha for exact positions"
  fi
fi

work="$RUNNER_TEMP/code-audit"
rm -rf "$work"
mkdir -p "$work/out"

prefix="$(g rev-parse --show-prefix 2>/dev/null || true)"
case "$prefix" in *$'\n'*) fail "unexpected rev-parse output" ;; esac
repo_root="$(g rev-parse --show-toplevel 2>/dev/null || true)"
case "$repo_root" in *$'\n'*) fail "unexpected rev-parse output" ;; esac

# Copy one file of the trusted commit (as stored: cat-file blob applies no
# filter or textconv) to $RUNNER_TEMP. Prints the copy's path, or nothing.
trusted_copy() {
  local rel="$1" dest="$2"
  [ -n "$trusted_ref" ] || return 0
  if g cat-file -e "$trusted_ref:$prefix$rel" 2>/dev/null; then
    g cat-file blob "$trusted_ref:$prefix$rel" > "$dest"
    echo "$dest"
  fi
}

ignore_file="$(trusted_copy .code-audit-ignore "$work/ignore.yml")"

baseline_file=""
if [ -n "$INPUT_BASELINE" ]; then
  case "$INPUT_BASELINE" in
    /*|*..*|*$'\n'*|*\\*) fail "baseline must be a path inside the repository, without '..'" ;;
  esac
  baseline_file="$(trusted_copy "$INPUT_BASELINE" "$work/baseline.json")"
  if [ -z "$baseline_file" ]; then
    echo "::warning::code-audit: baseline $INPUT_BASELINE is not in commit ${trusted_ref:-<none>}; scanning without a baseline"
  fi
fi

# ---- the Action's own source, built outside the workspace -------------------
src="$work/src"
mkdir -p "$src"
(cd "$ACTION_PATH" && tar --exclude=./.git --exclude=./node_modules --exclude='./packages/*/node_modules' \
  --exclude='./packages/*/dist' --exclude=./.audit --exclude='./.tmp-test-*' -cf - .) | tar -C "$src" -xf -
package_json="$(node -e 'process.stdout.write(require("node:path").relative(process.argv[1], process.argv[2]))' \
  "$workspace" "$src/package.json")"

fork=false
if [ "$is_pr" = true ] && [ -n "${PR_HEAD_REPO:-}" ] && [ "$PR_HEAD_REPO" != "${GITHUB_REPOSITORY:-}" ]; then
  fork=true
fi

comment="$INPUT_COMMENT"
if [ "$is_pr" != true ]; then comment=false; fi

out mode "$mode"
out target "$target"
out src "$src"
out out "$work/out"
out package-json "$package_json"
out base-sha "$since"
out head-sha "$head_sha"
out pr-number "$pr_number"
out ignore-file "$ignore_file"
out baseline-file "$baseline_file"
out fail-on "$INPUT_FAIL_ON"
out min-confidence "$INPUT_MIN_CONFIDENCE"
out engines "$INPUT_ENGINES"
out offline "$INPUT_OFFLINE"
out upload-sarif "$INPUT_UPLOAD_SARIF"
out comment "$comment"
out artifact-name "$INPUT_ARTIFACT_NAME"
out path-prefix "$prefix"
out repo-root "$repo_root"
out fork "$fork"

echo "code-audit: mode $mode${since:+, changed lines since $since}${ignore_file:+, ignore file from $trusted_ref}${baseline_file:+, baseline from $trusted_ref}"

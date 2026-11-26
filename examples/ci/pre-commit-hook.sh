#!/usr/bin/env bash
# code-audit pre-commit hook.
#
# This script is provided as a reference and has NOT been executed on a real
# pre-commit framework. Install it by copying it to .git/hooks/pre-commit (or
# wiring it into your pre-commit configuration) and making it executable:
#
#   cp examples/ci/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# It runs a quick incremental scan of the changes since HEAD and blocks the
# commit when new findings reach the fail-on threshold. The hook requires the
# `code-audit` CLI to be on PATH.

set -euo pipefail

if ! command -v code-audit >/dev/null 2>&1; then
  echo "code-audit: CLI not found on PATH; skipping pre-commit scan." >&2
  exit 0
fi

echo "code-audit: scanning changes since HEAD (quick profile)..." >&2
code-audit scan . --since HEAD --ci --profile quick
status=$?

if [ "$status" -eq 1 ]; then
  echo "code-audit: new findings detected; commit blocked." >&2
  echo "code-audit: review the report, fix the issues, or add a .code-audit-ignore entry." >&2
  exit 1
fi

if [ "$status" -eq 2 ]; then
  echo "code-audit: runtime error during scan; commit blocked." >&2
  exit 1
fi

exit 0
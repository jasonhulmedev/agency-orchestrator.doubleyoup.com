#!/usr/bin/env sh
#
# Conftest (OPA/Rego) policy checks for agency-orchestrator.doubleyoup.com's structured config.
#
# Semgrep reads source code; conftest reads config documents. The split is deliberate: a rule
# belongs here when its target is a workflow, and in .policy-as-code/.semgrep when its target is
# TypeScript.
#
# Each target set gets its own policy directory and its own invocation, because every policy uses
# `package main` and would otherwise be applied to every document. This repo has one target set
# today (the GitHub workflows); a second one gets its own `run_policy_dir` line here, not a
# second glob in the existing call.
#
# Usage:
#   scripts/conftest.sh                 check every target (the default)
#   scripts/conftest.sh verify          run the Rego unit tests instead
#   scripts/conftest.sh test --no-color plain output
#
# conftest exits non-zero on a `deny`. A `warn` is advisory and does not fail the run unless you
# pass --fail-on-warn.
#
# Install conftest with (CI pins the same version and checks the tarball's sha256):
#   V=0.69.0
#   curl -sSL -O "https://github.com/open-policy-agent/conftest/releases/download/v${V}/conftest_${V}_Linux_x86_64.tar.gz"
#   tar -xzf "conftest_${V}_Linux_x86_64.tar.gz" conftest && install -m 0755 conftest ~/.local/bin/conftest
set -eu

# Run from the repo root so every policy and target path below is repo-relative.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

if ! command -v conftest > /dev/null 2>&1; then
  echo "conftest is not on PATH. See the install command in this script's header." >&2
  exit 127
fi

POLICY_ROOT=.policy-as-code/.conftest

MODE="test"
if [ "$#" -gt 0 ]; then
  case "$1" in
    test|verify)
      MODE=$1
      shift
      ;;
  esac
fi

# Track the worst exit code instead of stopping at the first failure, so one bad document does
# not hide the state of the others.
WORST_STATUS=0

run_policy_dir() {
  policy_dir=$1
  shift

  if [ "$MODE" = "verify" ]; then
    echo "--- verify $policy_dir"
    conftest verify --policy "$policy_dir" "$@" || WORST_STATUS=$?
    return 0
  fi

  echo "--- test $policy_dir"
  conftest test --policy "$policy_dir" "$@" || WORST_STATUS=$?
}

if [ "$MODE" = "verify" ]; then
  run_policy_dir "$POLICY_ROOT/workflows" "$@"
else
  # EVERY workflow, not one named file. The policy exists to catch a job that declares no
  # `permissions:`, interpolates a github.event value into a `run:` script, or runs an action
  # that is not pinned to a commit SHA — and a workflow nobody remembered to list here is
  # exactly the one that would carry it. Globbed so a new workflow is covered the day it is
  # added.
  run_policy_dir "$POLICY_ROOT/workflows" .github/workflows/*.yml "$@"
fi

exit "$WORST_STATUS"

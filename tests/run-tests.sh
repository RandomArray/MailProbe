#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/mailprobe.sh"

echo "Running MailProbe small test harness"

FAIL=0

expect_output_contains() {
  local cmd=("$@")
  local expected="$1"
  shift
}

run_test() {
  local name="$1"; shift
  echo "-- TEST: $name"
  if "$@" >/tmp/test_output 2>&1; then
    cat /tmp/test_output | sed -n '1,120p'
    echo " RESULT: exit 0"
  else
    echo " RESULT: NON-ZERO EXIT"
    FAIL=1
  fi
}

run_test "help" "$SCRIPT" -h

# Check help output contains 'Usage' or 'MailProbe'
if ! grep -q "Usage" /tmp/test_output && ! grep -q "MailProbe" /tmp/test_output; then
  echo "FAIL: help did not print Usage or MailProbe header"
  FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
  echo "One or more tests failed"
  exit 1
fi

echo "All tests passed"

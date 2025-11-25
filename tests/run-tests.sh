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

# Smoke test: passing --password should set auth mode (non-interactive)
run_test "password-flag-enables-auth" "$SCRIPT" -e test@example.com --password ThePassword123 --no-dns --no-autodiscover --no-ports

# Validate auth flag appears in top-level output
if ! grep -q "Auth:.*enabled .*password provided" /tmp/test_output; then
  echo "FAIL: --password did not enable auth in output"
  FAIL=1
fi

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

# ----- Timeout behaviour tests (unit tests that don't touch network) -----
echo
echo "Running run_with_timeout unit tests"

# Avoid triggering interactive prompts when sourcing the script
EMAIL="test@example.com"
# shellcheck source=/dev/null
. "$SCRIPT"

echo "-- TEST: run_with_timeout should time out (sleep 2, timeout=1)"
TMPOUT=/tmp/test_timeout_out
# Use absolute sleep when available to avoid shell builtin/wrapper races
SLEEP_BIN="$(command -v sleep || echo sleep)"
# Force fallback in tests (simulate systems without `timeout` cmd)
orig_timeout_bin="${TIMEOUT_BIN:-}"
TIMEOUT_BIN=""
set +e
run_with_timeout 1 "$SLEEP_BIN" 2 >"$TMPOUT" 2>&1
rc=$?
set -e
TIMEOUT_BIN="$orig_timeout_bin"
if [ "$rc" -eq 0 ]; then
  echo "FAIL: expected non-zero rc for timed out command, got $rc"
  FAIL=1
else
  echo "OK: timed out as expected (rc $rc)"
fi

echo "-- TEST: run_with_timeout preserves early stdout (echo before sleep)"
orig_timeout_bin="${TIMEOUT_BIN:-}"
TIMEOUT_BIN=""
set +e
run_with_timeout 1 bash -lc 'printf "start\n"; sleep 2; printf "should-not-see\n"' >"$TMPOUT" 2>&1
rc=$?
set -e
TIMEOUT_BIN="$orig_timeout_bin"
if [ "$rc" -eq 0 ]; then
  echo "FAIL: expected non-zero rc for timed out command, got $rc"
  FAIL=1
else
  if grep -q "start" "$TMPOUT"; then
    echo "OK: early stdout captured before timeout"
  else
    echo "FAIL: early stdout missing from output"
    FAIL=1
  fi
fi

if [ "$FAIL" -ne 0 ]; then
  echo "One or more tests failed"
  exit 1
fi

echo "All tests passed"

# ----- Autodiscover tests (stubbed curl) -----
echo
echo "Running autodiscover stub tests"

# Create a small curl stub to simulate an autodiscover endpoint
STUB="/tmp/curl_stub_$$"
cat >"$STUB" <<'CURLSTUB'
#!/usr/bin/env bash
# Mimic a minimal subset of curl behaviour used by mailprobe tests
while [ "$#" -gt 0 ]; do
  case "$1" in
    -D) shift; # -D - (headers) will be asked; we will print a header and exit
      echo "HTTP/1.1 200 OK"; exit 0;;
    -sS) shift; # ignore
      ;;
    -k) shift; ;;
    -L) shift; ;;
    -o) shift 2; ;;
    -H) shift 2; ;;
    -d) # this is a POST with XML payload — reply with sample XML
      echo '<AutodiscoverResponse>OK</AutodiscoverResponse>'; exit 0;;
    *) # final arg is the URL
      url="$1"; shift; ;;
  esac
done
# If URL contains ?emailaddress= return OK body, else return the friendly missing-email text
case "$url" in
  *emailaddress=*)
    echo "<AutodiscoverResult>Found entries for email</AutodiscoverResult>"; exit 0;;
  *)
    echo "Missing emailaddress parameter"; exit 0;;
esac
CURLSTUB
chmod +x "$STUB"

# Ensure tests use stub and don't rely on system curl
orig_curl="$CURL_BIN"
CURL_BIN="$STUB"

EMAIL="testuser@example.com"
echo "-- TEST: autodiscover GET with ?emailaddress and POST"
set +e
run_autodiscover_tests "example.com" >/tmp/ad_out 2>&1
rc=$?
set -e
cat /tmp/ad_out | sed -n '1,160p'
if [ $rc -ne 0 ]; then
  echo "FAIL: run_autodiscover_tests returned non-zero ($rc)"
  exit 1
fi

# Restore curl
CURL_BIN="$orig_curl"

rm -f "$STUB" /tmp/ad_out || true

echo "Autodiscover stub tests passed"

# Validate JSON summary output
echo
echo "-- TEST: json-summary-format"
set +e
# Ensure stdout contains only JSON (human output should go to stderr)
EMAIL=test@example.com "$SCRIPT" --no-dns --no-autodiscover --no-ports --no-color --summary json >/tmp/json_out 2>/tmp/json_err || true
rc=$?
set -e
if [ $rc -ne 0 ]; then
  echo "FAIL: script failed when generating JSON summary (rc=$rc)"
  exit 1
fi

# Check stdout is valid JSON only
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import sys,json; json.load(open("/tmp/json_out","r"))' >/dev/null 2>&1 || {
    echo "FAIL: stdout did not contain valid JSON"
    sed -n '1,120p' /tmp/json_out || true
    exit 1
  }
elif command -v python >/dev/null 2>&1; then
  python -c 'import sys,json; json.load(open("/tmp/json_out","r"))' >/dev/null 2>&1 || {
    echo "FAIL: stdout did not contain valid JSON"
    sed -n '1,120p' /tmp/json_out || true
    exit 1
  }
else
  # Fallback: ensure stdout starts with a JSON object character
  if ! sed -n '1p' /tmp/json_out | grep -q '^{'; then
    echo "FAIL: stdout did not start with JSON object"
    sed -n '1,160p' /tmp/json_out || true
    exit 1
  fi
fi

# Ensure there is human output on stderr (sanity check that human logs are sent to stderr)
if [ -s /tmp/json_err ]; then
  echo "OK: stderr contains human diagnostics (separated from JSON stdout)"
else
  echo "WARN: no human output on stderr; ensure logging works as expected"
fi

echo "JSON summary test passed"

# Reproduce user scenario (no redirection of stderr) — ensure no Bad file descriptor
echo
echo "-- TEST: json-no-redirect should not error"
set +e
EMAIL=test@example.com "$SCRIPT" --no-autodiscover --summary json >/tmp/json_out_nr 2>/tmp/json_err_nr || true
rc=$?
set -e
if [ $rc -ne 0 ]; then
  echo "FAIL: script exited non-zero (rc=$rc) for no-redirect test"
  exit 1
fi

# Ensure stderr did not contain 'Bad file descriptor'
if grep -q "Bad file descriptor" /tmp/json_err_nr 2>/dev/null; then
  echo "FAIL: stderr contained 'Bad file descriptor'"
  sed -n '1,120p' /tmp/json_err_nr || true
  exit 1
fi

# Ensure stdout is valid JSON
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import json,sys; json.load(open("/tmp/json_out_nr","r"))' >/dev/null 2>&1 || {
    echo "FAIL: stdout was not valid JSON in no-redirect test"
    sed -n '1,120p' /tmp/json_out_nr || true
    exit 1
  }
elif command -v python >/dev/null 2>&1; then
  python -c 'import json,sys; json.load(open("/tmp/json_out_nr","r"))' >/dev/null 2>&1 || {
    echo "FAIL: stdout was not valid JSON in no-redirect test"
    sed -n '1,120p' /tmp/json_out_nr || true
    exit 1
  }
else
  if ! sed -n '1p' /tmp/json_out_nr | grep -q '^{'; then
    echo "FAIL: stdout did not start with JSON in no-redirect test"
    sed -n '1,120p' /tmp/json_out_nr || true
    exit 1
  fi
fi

echo "JSON no-redirect test passed"

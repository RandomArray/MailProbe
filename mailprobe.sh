#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# MailProbe — email diagnostics and autodiscover tester (mailprobe.sh)
# https://github.com/RandomArray/MailProbe
# Requires: bash, and (recommended) dig/host, openssl, nc/curl

set -u -o pipefail

############################
# Colors / Styling
############################
USE_COLOR=1

if ! [ -t 1 ]; then
  USE_COLOR=0
fi

if [ "${NO_COLOR:-0}" -eq 1 ]; then
  USE_COLOR=0
fi


if [ "$USE_COLOR" -eq 1 ] && command -v tput >/dev/null 2>&1; then
  GREEN=$(tput setaf 2)
  RED=$(tput setaf 1)
  YELLOW=$(tput setaf 3)
  CYAN=$(tput setaf 6)
  MAGENTA=$(tput setaf 5)
  BOLD=$(tput bold)
  RESET=$(tput sgr0)
else
  GREEN=""; RED=""; YELLOW=""; CYAN=""; MAGENTA=""; BOLD=""; RESET=""
fi

CHECK_OK="${GREEN}✅${RESET}"
CHECK_FAIL="${RED}❌${RESET}"
CHECK_WARN="${YELLOW}⚠️${RESET}"
SPARK="${MAGENTA}✴${RESET}"

############################
# Logging helpers
############################
INFO_ICON="🔎"

# Summary collectors: record issues and discovered config values to show a
# compact summary at the end of a run. These arrays are intentionally
# lightweight (plain text) so they are safe to source or print in CI.
declare -a SUMMARY_ISSUES=()
declare -a SUMMARY_FOUND=()
declare -a SUMMARY_PORTS=()
declare -a SUMMARY_TLS=()
declare -a SUMMARY_AUTH=()

# Track warnings/errors in the printable summary so the user gets an at-a-glance
# view of what to check after the run. Keep printing behaviour for visual
# output but also append plain text to the summary arrays.
# (log functions are defined later; we define detailed versions after
# the summary arrays so they can reference SUMMARY_FORMAT at runtime)

############################
# Banner
############################
print_banner() {
  # Use colored and concise banner header
  printf "%s\n" "${MAGENTA}${BOLD}MailProbe${RESET} by ${CYAN}RandomArray${RESET} - ${BOLD}MailProbe (open-source)${RESET}"
  printf "%s\n\n" "${CYAN}Light-weight diagnostics and connectivity probe for mail delivery/auth${RESET}"
}

############################
# Usage
############################
usage() {
  cat <<EOF
${BOLD}MailProbe (mailprobe)${RESET}

Usage:
  $(basename "$0") [options]

Options:
  -e, --email EMAIL         Email address to test (e.g. user@example.com)
  -u, --user USERNAME       Login username (defaults to EMAIL)
  -d, --domain DOMAIN       Domain to test (defaults to part after @ in EMAIL)
  -S, --server SERVER       Explicit mail server (host) to test
      --imap-server HOST    IMAP server host (default: SERVER or derived)
      --pop-server  HOST    POP3 server host (default: SERVER or derived)
      --smtp-server HOST    SMTP server host (default: SERVER or derived)
  -p, --prompt-password     Prompt for password and run login tests
  --password PASSWORD       Provide password on command line (insecure; prefer env)
  -t, --timeout SECONDS     TCP/connect timeout in seconds (default: 5)
  --use-mx                  Prefer using MX host(s) for SMTP/server selection
  --show-body               Show HTTP response bodies for autodiscover/autoconfig (default ON)
  --no-show-body            Do not fetch or display HTTP response bodies
  --max-body-lines NUM      Maximum lines of HTTP body to print (default: 120)
      --no-autodiscover     Skip autodiscover/autoconfig HTTP tests
      --no-dns              Skip DNS tests
      --no-ports            Skip port/connectivity tests
      --test-insecure-ports Also test legacy plaintext ports (143/110/25). These are skipped by default.
      --no-color            Disable color output
      --summary FORMAT      Emit a short machine-readable summary. Supported: plain (default), json
           --summary-format FORMAT
                            Alias for --summary (for backwards-compatibility)
  -h, --help                Show this help

Examples:
  # Provide password securely via environment (recommended):
  EMAIL_PASS=MySecret123 $(basename "$0") -e user@example.com -u user -p

  # Or pass password on command line (insecure; visible in process list):
  $(basename "$0") -e user@example.com -u user --password MySecret123 --use-mx
  $(basename "$0") -e user@example.com -S mail.example.com --no-autodiscover

  # JSON-only output example: route human diagnostics to stderr so stdout contains
  # only the machine-readable JSON summary.
  # $(basename "$0") -e user@example.com --no-dns --no-autodiscover --no-ports --summary json 2>/dev/null

EOF
}

############################
# Tool checks
log_info()  {
  if [ "${SUMMARY_FORMAT:-plain}" = "json" ]; then
    # When emitting machine output, route human diagnostics to stderr
    echo -e "${CYAN}${INFO_ICON}${RESET} $*" >&2
  else
    echo -e "${CYAN}${INFO_ICON}${RESET} $*"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Logging helpers (global) — route human output to stderr in JSON mode
log_ok() {
  if [ "${SUMMARY_FORMAT:-plain}" = "json" ]; then
    echo -e "${CHECK_OK} ${GREEN}$*${RESET}" >&2
  else
    echo -e "${CHECK_OK} ${GREEN}$*${RESET}"
  fi
  SUMMARY_FOUND+=("$*")
}

log_warn() {
  if [ "${SUMMARY_FORMAT:-plain}" = "json" ]; then
    echo -e "${CHECK_WARN} ${YELLOW}$*${RESET}" >&2
  else
    echo -e "${CHECK_WARN} ${YELLOW}$*${RESET}"
  fi
  SUMMARY_ISSUES+=("$*")
}

log_error() {
  if [ "${SUMMARY_FORMAT:-plain}" = "json" ]; then
    echo -e "${CHECK_FAIL} ${RED}$*${RESET}" >&2
  else
    echo -e "${CHECK_FAIL} ${RED}$*${RESET}" >&2
  fi
  SUMMARY_ISSUES+=("$*")
}

require_one_of() {
  local name="$1"; shift
  for c in "$@"; do
    if have_cmd "$c"; then
      echo "$c"
      return 0
    fi
  done
  log_warn "Missing recommended tool(s) for $name: $*"
  return 1
}

############################
# DNS helpers
############################
DNS_TOOL="$(require_one_of DNS dig host)"

dns_query() {
  local type="$1"
  local name="$2"

  if [ "$DNS_TOOL" = "dig" ]; then
    dig +short "$name" "$type" 2>/dev/null
  elif [ "$DNS_TOOL" = "host" ]; then
    host -t "$type" "$name" 2>/dev/null | awk '{for(i=4;i<=NF;i++) printf "%s%s", $i, (i==NF?ORS:OFS)}'
  else
    return 1
  fi
}

############################
# Port helpers
############################
NC_TOOL="$(require_one_of 'TCP connection testing' nc ncat netcat || echo "")"

tcp_test() {
  local host="$1" port="$2" label="$3" timeout="${4:-$TCP_TIMEOUT}"

  # Quick check using bash's /dev/tcp if available. Use timeout wrapper
  # when available to avoid indefinite blocking.
  log_info "[$label] Attempting TCP connect to $host:$port (timeout ${timeout}s)"
  # Try /dev/tcp (bash builtin) but always enforce a timeout using
  # run_with_timeout so this never blocks indefinitely.
  if run_with_timeout "${timeout}" bash -c "exec 3<>/dev/tcp/$host/$port" >/dev/null 2>&1; then
    log_ok "[$label] TCP $host:$port reachable (via /dev/tcp)"
    SUMMARY_PORTS+=("[$label] TCP $host:$port reachable (via /dev/tcp)")
    return 0
  fi

  if [ -n "$NC_TOOL" ]; then
    # Try the most common netcat invocation first (with timeout)
    if run_with_timeout "${timeout}" "$NC_TOOL" -z -w "$timeout" "$host" "$port" >/dev/null 2>&1; then
      log_ok "[$label] TCP $host:$port reachable (via $NC_TOOL -z)"
      SUMMARY_PORTS+=("[$label] TCP $host:$port reachable (via $NC_TOOL -z)")
      return 0
    fi

    # Some netcat variants are a bit different; try a minimal probe
    if run_with_timeout "${timeout}" "$NC_TOOL" -z "$host" "$port" >/dev/null 2>&1; then
      log_ok "[$label] TCP $host:$port reachable (via $NC_TOOL -z fallback)"
      SUMMARY_PORTS+=("[$label] TCP $host:$port reachable (via $NC_TOOL -z fallback)")
      return 0
    fi
  fi

  log_error "[$label] TCP $host:$port NOT reachable"
  SUMMARY_PORTS+=("[$label] TCP $host:$port NOT reachable")
  return 1
}

############################
# TLS helpers
############################
OPENSSL_BIN="$(require_one_of 'TLS handshakes' openssl || echo "")"
BASE64_BIN="$(require_one_of 'base64' base64 || echo "")"
TIMEOUT_BIN="$(require_one_of 'timeout' timeout gtimeout || echo "")"
# When performing the fallback background launch we prefer to run the target
# in a new session so we can reliably kill the whole process group on timeout.
SESS_BIN="$(require_one_of 'session leader' setsid || echo "")"

# run_with_timeout: execute a command with a timeout (seconds). Prefer the
# system-provided timeout command when available. When that's missing, fall
# back to a lightweight bash-managed timeout to avoid indefinite blocking in
# environments where /dev/tcp or openssl may hang.
#
# Usage: run_with_timeout SECONDS cmd args...
run_with_timeout() {
  local timeout_seconds="$1"; shift

  if [ -n "$TIMEOUT_BIN" ]; then
    # Use system timeout when available — preserves usual exit codes and
    # leaves stdout/stderr behavior untouched.
    "$TIMEOUT_BIN" "${timeout_seconds}s" "$@"
    return $?
  fi

  # Fallback: run command in background but capture stdout/stderr to
  # temporary files so callers can capture output via command substitution.
  local stdout_file
  stdout_file=$(mktemp) || stdout_file=/tmp/mailprobe_stdout_$$
  local stderr_file
  stderr_file=$(mktemp) || stderr_file=/tmp/mailprobe_stderr_$$

  # Launch the command under a shell that uses exec so the spawned process
  # replaces the shell — this ensures $! matches the long-running command
  # rather than a short-lived wrapper (fixes race where wrappers exit).
  local cmd=("$@")
  if [ -n "$SESS_BIN" ]; then
    # Use setsid to run in new session so we can kill the whole group reliably
    $SESS_BIN bash -c 'exec "$@"' -- "${cmd[@]}" >"$stdout_file" 2>"$stderr_file" &
  else
    bash -c 'exec "$@"' -- "${cmd[@]}" >"$stdout_file" 2>"$stderr_file" &
  fi
  local pid=$!

  local max_ticks=$((timeout_seconds * 10))
  local ticks=0
  if [ "${DEBUG_RWT:-0}" -eq 1 ]; then
    echo "DEBUG run_with_timeout: pid=$pid max_ticks=$max_ticks" >&2
  fi
  while kill -0 "$pid" >/dev/null 2>&1; do
    if [ "$ticks" -ge "$max_ticks" ]; then
      if [ "${DEBUG_RWT:-0}" -eq 1 ]; then
        echo "DEBUG run_with_timeout: timed out (ticks=$ticks) killing pid=$pid" >&2
      fi
      # Timed out; attempt polite termination then force.
      if [ -n "$SESS_BIN" ]; then
        # kill the whole process group
        kill -TERM -"$pid" >/dev/null 2>&1 || true
      else
        kill "$pid" >/dev/null 2>&1 || true
      fi
      # Allow a short grace period for the child process to flush any buffered
      # stdout/stderr to disk before we escalate to SIGKILL. Small CI images
      # can be tight on scheduling; increase the wait slightly to reduce
      # flaky missing-stdout failures.
      sleep 0.20
      if [ -n "$SESS_BIN" ]; then
        kill -9 -"$pid" >/dev/null 2>&1 || true
      else
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
      wait "$pid" 2>/dev/null || true
      # Emit whatever the command produced before timing out.
      cat "$stdout_file"
      cat "$stderr_file" >&2
      rm -f "$stdout_file" "$stderr_file" 2>/dev/null || true
      return 124
    fi
    sleep 0.1
    ticks=$((ticks + 1))
  done

  wait "$pid"
  local rc=$?
  cat "$stdout_file"
  cat "$stderr_file" >&2
  rm -f "$stdout_file" "$stderr_file" 2>/dev/null || true
  return $rc
}

tls_probe() {
  local host="$1" port="$2" label="$3" starttls_proto="${4:-}" timeout="${5:-$TCP_TIMEOUT}"

  if [ -z "$OPENSSL_BIN" ]; then
    log_warn "[$label] Skipping TLS probe (openssl not available)"
    return 1
  fi

  log_info "[$label] Probing TLS on $host:$port ${SPARK} (timeout ${timeout}s)"

  # Build the openssl command as an array (avoid placing redirections inside
  # the array initializer which is a syntax error in strict shells)
  local cmd=( "$OPENSSL_BIN" s_client -crlf -verify_quiet -showcerts )

  # Add starttls argument before connect if requested (some openssl versions
  # dislike starttls after connect)
  if [ -n "$starttls_proto" ]; then
    cmd+=( -starttls "$starttls_proto" )
  fi

  cmd+=( -connect "${host}:${port}" -servername "$host" )

  local out
  # Redirect stderr to /dev/null when running openssl so our parsing won't
  # be polluted by progress messages. We also feed /dev/null to stdin.
  # Use run_with_timeout to protect against environments where `timeout`
  # isn't installed and openssl may block indefinitely. Capture both stdout
  # and stderr so we can parse handshake output consistently.
  out=$(run_with_timeout "${timeout}" "${cmd[@]}" </dev/null 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    log_error "[$label] TLS handshake FAILED on $host:$port (timeout or error)"
    SUMMARY_TLS+=("[$label] TLS handshake FAILED on $host:$port (timeout or error)")
    return 1
  fi

  if echo "$out" | grep -qi "Verify return code: 0"; then
    log_ok "[$label] TLS cert verified OK on $host:$port"
    SUMMARY_TLS+=("[$label] TLS cert verified OK on $host:$port")
  else
    log_warn "[$label] TLS handshake OK but certificate verification may have issues"
    SUMMARY_TLS+=("[$label] TLS handshake OK but certificate verification may have issues on $host:$port")
  fi

  local subject issuer notAfter
  subject=$(printf "%s" "$out" | grep -m1 "subject=" | sed 's/.*subject=//')
  issuer=$(printf "%s" "$out" | grep -m1 "issuer=" | sed 's/.*issuer=//')
  notAfter=$(printf "%s" "$out" | grep -m1 "notAfter=" | sed 's/.*notAfter=//')

  echo "   ${BOLD}Subject:${RESET} $subject"
  echo "   ${BOLD}Issuer:${RESET}  $issuer"
  echo "   ${BOLD}Expires:${RESET} $notAfter"
}

############################
# Auth tests (IMAP/POP3)
############################
EMAIL="${EMAIL:-}"
EMAIL_USER="${EMAIL_USER:-}"
EMAIL_PASS="${EMAIL_PASS:-}"
DO_AUTH=0

imap_auth_test() {
  local host="$1" port="$2" label="$3" timeout="${4:-$TCP_TIMEOUT}"

  if [ "$DO_AUTH" -ne 1 ]; then
    log_warn "[$label] Skipping IMAP auth test (no password supplied)"
    return 0
  fi
  if [ -z "$OPENSSL_BIN" ]; then
    log_warn "[$label] Skipping IMAP auth test (openssl not available)"
    return 0
  fi

  log_info "[$label] Testing IMAP LOGIN on $host:$port (timeout ${timeout}s)"

  local imap_cmd out
  imap_cmd="a1 LOGIN \"$EMAIL_USER\" \"$EMAIL_PASS\"\r\na2 LOGOUT\r\n"

    if [ "$port" -eq 143 ]; then
      out=$(printf "%b" "$imap_cmd" | run_with_timeout "${timeout}" "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" -starttls imap 2>&1)
      rc=$?
    else
      out=$(printf "%b" "$imap_cmd" | run_with_timeout "${timeout}" "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" 2>&1)
      rc=$?
    fi

  if echo "$out" | grep -qi "^a1 OK"; then
    log_ok "[$label] IMAP LOGIN succeeded for $EMAIL_USER"
    SUMMARY_AUTH+=("[IMAP] LOGIN succeeded for $EMAIL_USER on $host:$port")
  else
    log_error "[$label] IMAP LOGIN appears to have FAILED for $EMAIL_USER"
    SUMMARY_AUTH+=("[IMAP] LOGIN FAILED for $EMAIL_USER on $host:$port")
    echo "   ${YELLOW}Server said:${RESET}"
    echo "$out" | sed 's/^/     /' | head -n 6
  fi
}

pop3_auth_test() {
  local host="$1" port="$2" label="$3" timeout="${4:-$TCP_TIMEOUT}"

  if [ "$DO_AUTH" -ne 1 ]; then
    log_warn "[$label] Skipping POP3 auth test (no password supplied)"
    return 0
  fi
  if [ -z "$OPENSSL_BIN" ]; then
    log_warn "[$label] Skipping POP3 auth test (openssl not available)"
    return 0
  fi

  log_info "[$label] Testing POP3 USER/PASS on $host:$port (timeout ${timeout}s)"

  local pop_cmd out
  pop_cmd="USER $EMAIL_USER\r\nPASS $EMAIL_PASS\r\nQUIT\r\n"

  if [ "$port" -eq 110 ]; then
    out=$(printf "%b" "$pop_cmd" | run_with_timeout "${timeout}" "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" -starttls pop3 2>&1)
    rc=$?
  else
    out=$(printf "%b" "$pop_cmd" | run_with_timeout "${timeout}" "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" 2>&1)
    rc=$?
  fi

  if echo "$out" | grep -qi "+OK"; then
    log_ok "[$label] POP3 login returned +OK for $EMAIL_USER"
    SUMMARY_AUTH+=("[POP3] LOGIN succeeded for $EMAIL_USER on $host:$port")
  else
    log_error "[$label] POP3 login appears to have FAILED for $EMAIL_USER"
    SUMMARY_AUTH+=("[POP3] LOGIN FAILED for $EMAIL_USER on $host:$port")
    echo "   ${YELLOW}Server said:${RESET}"
    echo "$out" | sed 's/^/     /' | head -n 6
  fi
}

############################
# DNS test suite
############################
run_dns_tests() {
  local domain="$1"

  if [ -z "$DNS_TOOL" ]; then
    log_warn "DNS tools not available, skipping DNS tests"
    return
  fi

  echo
  echo "${MAGENTA}${BOLD}==== DNS TESTS for $domain ====${RESET}"

  log_info "${BOLD}${MAGENTA}MX records:${RESET}"
  local mx
  mx=$(dns_query MX "$domain" || true)
  if [ -n "$mx" ]; then
    awk '{print "  " $0}' <<< "$mx"
  else
    log_warn "No MX records found for $domain"
  fi

  log_info "${BOLD}${MAGENTA}A/AAAA for $domain:${RESET}"
  local aaaa
  aaaa=$(dns_query A "$domain"; dns_query AAAA "$domain" || true)
  if [ -n "$aaaa" ]; then
    awk '{print "  " $0}' <<< "$aaaa"
  else
    log_warn "No A/AAAA records for $domain"
  fi

  log_info "${BOLD}${MAGENTA}SPF (TXT) for $domain:${RESET}"
  local txt
  txt=$(dns_query TXT "$domain" || true)
  echo "$txt" | grep -i "v=spf1" | sed 's/^/  /' || log_warn "No SPF TXT record found"

  log_info "${BOLD}${MAGENTA}DMARC for _dmarc.$domain:${RESET}"
  local dmarc
  dmarc=$(dns_query TXT "_dmarc.$domain" || true)
  if [ -n "$dmarc" ]; then
    awk '{print "  " $0}' <<< "$dmarc"
  else
    log_warn "No DMARC record found"
  fi

  log_info "${BOLD}${MAGENTA}Autodiscover/Autoconfig hostnames:${RESET}"
  for host in "autodiscover.$domain" "autoconfig.$domain"; do
    local rec
    rec=$(dns_query A "$host"; dns_query CNAME "$host" || true)
    if [ -n "$rec" ]; then
      log_ok "${GREEN}$host resolves to:${RESET}"
      awk '{print "  " $0}' <<< "$rec"
    else
      log_warn "$host has no A/CNAME record"
    fi
  done

  log_info "${BOLD}${MAGENTA}RFC6186 SRV records (IMAPS/POP3S/SUBMISSION):${RESET}"
  for srv in _imaps._tcp _pop3s._tcp _submission._tcp _imap._tcp _pop3._tcp _smtp._tcp; do
    local srvdata
    srvdata=$(dns_query SRV "$srv.$domain" || true)
    if [ -n "$srvdata" ]; then
      log_ok "$srv.$domain:"
      awk '{print "  " $0}' <<< "$srvdata"
    fi
  done
}

############################
# Autodiscover / Autoconfig HTTP tests
############################
CURL_BIN="$(require_one_of 'HTTP testing' curl wget || echo "")"

http_head() {
  local url="$1"
  if [ "$CURL_BIN" = "curl" ]; then
    curl -k -sS -o /dev/null -D - "$url" 2>/dev/null | head -n 1
  elif [ "$CURL_BIN" = "wget" ]; then
    wget --no-check-certificate --server-response --spider -q "$url" 2>&1 | head -n 1
  else
    echo "N/A"
  fi
}

# Fetch HTTP body for a URL; returns the body on stdout (no headers). We use
# --max-redirs and -L to follow redirects and suppress errors.
http_fetch() {
  local url="$1"
  if [ "$CURL_BIN" = "curl" ]; then
    curl -k -sS -L "$url" 2>/dev/null || true
  elif [ "$CURL_BIN" = "wget" ]; then
    wget --no-check-certificate -q -O - "$url" 2>/dev/null || true
  else
    return 1
  fi
}

run_autodiscover_tests() {
  local domain="$1"

  if [ -z "$CURL_BIN" ]; then
    log_warn "curl/wget not available, skipping autodiscover HTTP tests"
    return
  fi

  echo
  echo "${BOLD}==== AUTODISCOVER / AUTOCONFIG HTTP TESTS ====${RESET}"

  local urls=(
    "https://autodiscover.$domain/autodiscover/autodiscover.xml"
    "https://$domain/autodiscover/autodiscover.xml"
    "https://autoconfig.$domain/mail/config-v1.1.xml"
    "https://$domain/.well-known/autoconfig/mail/config-v1.1.xml"
  )

  for u in "${urls[@]}"; do
    local status
    status=$(http_head "$u" || true)
    # Inspect HTTP status and classify severity. 200=OK, 3xx=redirect (OK),
    # 401/403 => reachable but requires auth/forbidden (warn), other codes => error
    local code
    code=$(printf "%s" "$status" | sed -n 's/.*HTTP\/[^ ]* \([0-9][0-9][0-9]\).*/\1/p' || true)
    if [ -z "$code" ]; then
      # Some servers/clients may return empty status; treat as warn/reachable
      log_warn " Endpoint returned no HTTP status header: $u"
      echo "   Status: $status"
      code=""
    fi

    # If the endpoint complains about a missing email address and we have an
    # email available, try probing with a query parameter and also try an
    # Exchange-style SOAP POST to elicit a richer response.
    if [ -n "$EMAIL" ]; then
      # Try common query parameter variants
      for param in "emailaddress" "EmailAddress"; do
        local qurl
        qurl="${u}?${param}=${EMAIL}"
        log_info "   Trying GET with ?${param} for: $qurl"
        local qstatus
        qstatus=$(http_head "$qurl" || true)
        local qcode
        qcode=$(printf "%s" "$qstatus" | sed -n 's/.*HTTP\/[^ ]* \([0-9][0-9][0-9]\).*/\1/p' || true)
        if [ -n "$qcode" ] && [ "$qcode" != "" ]; then
          if [ "$qcode" = "200" ]; then
            log_ok "   GET ?${param} reachable: $qurl"
            if [ "${SHOW_BODY:-1}" -eq 1 ]; then
              log_info "   Fetching body (first ${MAX_BODY_LINES} lines) for: $qurl"
              http_fetch "$qurl" | sed -n "1,${MAX_BODY_LINES}p" | sed 's/^/     /' || true
            fi
            # If we got something useful, skip trying other params for this URL
            break
          else
            log_warn "   GET ?${param} returned HTTP ${qcode} for $qurl"
          fi
        fi
      done

      # Try Exchange SOAP POST (Autodiscover) if curl is available and the
      # endpoint still hasn't returned a useful 200 result from the GETs.
      if [ "$CURL_BIN" = "curl" ]; then
        log_info "   Trying Exchange Autodiscover SOAP POST to: $u"
        local soap_payload
        soap_payload="<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\"><Request><EMailAddress>${EMAIL}</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>"
        # Use run_with_timeout so we don't block when network is stale
        local post_out
        post_out=$(run_with_timeout "$TCP_TIMEOUT" "$CURL_BIN" -k -sS -H "Content-Type: text/xml; charset=utf-8" -d "$soap_payload" "$u" 2>/dev/null || true)
        if [ -n "$post_out" ]; then
          log_ok "   Autodiscover POST returned a body (truncated):"
          printf "%s" "$post_out" | sed -n "1,${MAX_BODY_LINES}p" | sed 's/^/     /'
        else
          log_warn "   Autodiscover POST returned no content or timed out"
        fi
      fi
    fi

    case "$code" in
      200)
        log_ok "Endpoint OK: $u"
        echo "   Status: $status"
        ;;
      301|302)
        log_ok "Endpoint redirects: $u"
        echo "   Status: $status"
        ;;
      401)
        log_warn "Endpoint reachable (authentication required): $u"
        echo "   Status: $status"
        ;;
      403)
        log_warn "Endpoint reachable (forbidden): $u"
        echo "   Status: $status"
        ;;
      '')
        # fall-through: we already warned above
        ;;
      *)
        log_error "Endpoint returned unexpected status: $u"
        echo "   Status: $status"
        ;;
    esac

    # Show body content for useful/diagnostic statuses when requested
    if [ "${SHOW_BODY:-1}" -eq 1 ] && { [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ] || [ "$code" = "401" ] || [ -z "$code" ]; }; then
      log_info "   Fetching body (first ${MAX_BODY_LINES} lines) for: $u"
      local body
      body=$(http_fetch "$u" || true)
      if [ -n "$body" ]; then
        echo "$body" | sed -n "1,${MAX_BODY_LINES}p" | sed 's/^/     /'
        if [ "$(printf "%s" "$body" | wc -l)" -gt "$MAX_BODY_LINES" ]; then
          echo "     ... (truncated, use --max-body-lines to show more)"
        fi
      else
        log_warn "   Could not fetch body for $u"
      fi
    fi

  done
}

############################
# Port / service tests
############################
run_port_tests() {
  local imap_host="$1" pop_host="$2" smtp_host="$3"

  echo
  echo "${MAGENTA}${BOLD}==== PORT / SERVICE CONNECTIVITY TESTS ====${RESET}"

  # IMAP
  log_info "${BOLD}${CYAN}IMAP checks for host:${RESET} ${BOLD}$imap_host${RESET}"
  local imap_ports=(993)
  if [ "${TEST_INSECURE_PORTS:-0}" -eq 1 ]; then
    imap_ports=(143 993)
  fi
  for port in "${imap_ports[@]}"; do
    log_info "${MAGENTA}--> IMAP port ${port}${RESET}"
    tcp_test "$imap_host" "$port" "IMAP" "$TCP_TIMEOUT" || true
    if [ "$port" -eq 143 ]; then
      tls_probe "$imap_host" "$port" "IMAP STARTTLS" "imap" "$TCP_TIMEOUT" || true
    else
      tls_probe "$imap_host" "$port" "IMAPS (993)" "" "$TCP_TIMEOUT" || true
    fi
    imap_auth_test "$imap_host" "$port" "IMAP AUTH" "$TCP_TIMEOUT" || true
  done

  # POP3
  log_info "${BOLD}${CYAN}POP3 checks for host:${RESET} ${BOLD}$pop_host${RESET}"
  local pop_ports=(995)
  if [ "${TEST_INSECURE_PORTS:-0}" -eq 1 ]; then
    pop_ports=(110 995)
  fi
  for port in "${pop_ports[@]}"; do
    log_info "${MAGENTA}--> POP3 port ${port}${RESET}"
    tcp_test "$pop_host" "$port" "POP3" "$TCP_TIMEOUT" || true
    if [ "$port" -eq 110 ]; then
      tls_probe "$pop_host" "$port" "POP3 STARTTLS" "pop3" "$TCP_TIMEOUT" || true
    else
      tls_probe "$pop_host" "$port" "POP3S (995)" "" "$TCP_TIMEOUT" || true
    fi
    pop3_auth_test "$pop_host" "$port" "POP3 AUTH" "$TCP_TIMEOUT" || true
  done

  # SMTP / Submission
  log_info "${BOLD}${CYAN}SMTP checks for host:${RESET} ${BOLD}$smtp_host${RESET}"
  local smtp_ports=(465 587)
  if [ "${TEST_INSECURE_PORTS:-0}" -eq 1 ]; then
    smtp_ports=(25 465 587)
  fi
  for port in "${smtp_ports[@]}"; do
    log_info "${MAGENTA}--> SMTP port ${port}${RESET}"
    tcp_test "$smtp_host" "$port" "SMTP" "$TCP_TIMEOUT" || true
    if [ "$port" -eq 25 ] || [ "$port" -eq 587 ]; then
      tls_probe "$smtp_host" "$port" "SMTP STARTTLS" "smtp" "$TCP_TIMEOUT" || true
    else
      tls_probe "$smtp_host" "$port" "SMTPS (465)" "" "$TCP_TIMEOUT" || true
    fi
    # SMTP AUTH test (if password provided)
    if [ "$DO_AUTH" -eq 1 ]; then
      smtp_auth_test "$smtp_host" "$port" "SMTP AUTH" "$TCP_TIMEOUT" || true
    fi
  done
}

smtp_auth_test() {
  local host="$1" port="$2" label="$3" timeout="${4:-$TCP_TIMEOUT}"

  if [ "$DO_AUTH" -ne 1 ]; then
    log_warn "[$label] Skipping SMTP auth test (no password supplied)"
    return 0
  fi
  if [ -z "$OPENSSL_BIN" ]; then
    log_warn "[$label] Skipping SMTP auth test (openssl not available)"
    return 0
  fi
  if [ -z "$BASE64_BIN" ]; then
    log_warn "[$label] Skipping SMTP auth test (base64 tool not available)"
    return 0
  fi

  log_info "[$label] Testing SMTP AUTH on $host:$port (timeout ${timeout}s)"

  # Choose STARTTLS for common submission ports
  local sargs=("$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}")
  if [ "$port" -eq 25 ] || [ "$port" -eq 587 ]; then
    sargs+=( -starttls smtp )
  fi

  local auth_cmd
  local user_b64 pass_b64
  user_b64=$(printf "%s" "$EMAIL_USER" | "$BASE64_BIN" | tr -d '\n')
  pass_b64=$(printf "%s" "$EMAIL_PASS" | "$BASE64_BIN" | tr -d '\n')

  auth_cmd="EHLO localhost\r\nAUTH LOGIN\r\n${user_b64}\r\n${pass_b64}\r\nQUIT\r\n"

  local out
  out=$(printf "%b" "$auth_cmd" | run_with_timeout "${timeout}" "${sargs[@]}" 2>&1)
  rc=$?

  if echo "$out" | grep -qiE "^235|Authentication successful"; then
    log_ok "[$label] SMTP AUTH succeeded for $EMAIL_USER"
    SUMMARY_AUTH+=("[SMTP] AUTH succeeded for $EMAIL_USER on $host:$port")
  else
    log_error "[$label] SMTP AUTH appears to have FAILED for $EMAIL_USER"
    SUMMARY_AUTH+=("[SMTP] AUTH FAILED for $EMAIL_USER on $host:$port")
    echo "   ${YELLOW}Server said:${RESET}"
    echo "$out" | sed 's/^/     /' | head -n 8
  fi
}

############################
# Argument parsing
############################
DOMAIN=""
SERVER=""
IMAP_SERVER=""
POP_SERVER=""
SMTP_SERVER=""
RUN_DNS=1
RUN_AUTODISCOVER=1
RUN_PORTS=1
TCP_TIMEOUT=5
USE_MX=0
SHOW_BODY=1
MAX_BODY_LINES=120
SUMMARY_FORMAT="plain" # other option: json
TEST_INSECURE_PORTS=0 # by default skip testing legacy plaintext ports (143/110/25)

while [ $# -gt 0 ]; do
  case "$1" in
    -e|--email)
      EMAIL="$2"; shift 2;;
    -u|--user)
      EMAIL_USER="$2"; shift 2;;
    -d|--domain)
      DOMAIN="$2"; shift 2;;
    -S|--server)
      SERVER="$2"; shift 2;;
    --imap-server)
      IMAP_SERVER="$2"; shift 2;;
    --pop-server)
      POP_SERVER="$2"; shift 2;;
    --smtp-server)
      SMTP_SERVER="$2"; shift 2;;
    --password)
      EMAIL_PASS="$2"; DO_AUTH=1; shift 2;;
    --show-body)
      SHOW_BODY=1; shift;;
    --no-show-body)
      SHOW_BODY=0; shift;;
    --max-body-lines)
      MAX_BODY_LINES="$2"; shift 2;;
    -t|--timeout)
      TCP_TIMEOUT="$2"; shift 2;;
    --use-mx|--prefer-mx)
      USE_MX=1; shift;;
    -p|--prompt-password)
      DO_AUTH=1; shift;;
    --no-autodiscover)
      RUN_AUTODISCOVER=0; shift;;
    --no-dns)
      RUN_DNS=0; shift;;
    --no-ports)
      RUN_PORTS=0; shift;;
    --test-insecure-ports)
      # Explicitly enable testing legacy plaintext ports (143,110,25)
      TEST_INSECURE_PORTS=1; shift;;
    --no-color)
      NO_COLOR=1; USE_COLOR=0; shift;;
    --summary|--summary-format)
      # Accept both: --summary json  or --summary-format json
      SUMMARY_FORMAT="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      log_error "Unknown option: $1"
      usage
      exit 1;;
  esac
done

############################
# Interactive prompts
############################
if [ -z "$EMAIL" ]; then
  read -rp "Enter email address to test (e.g. user@example.com): " EMAIL
fi

if [ -z "$EMAIL_USER" ]; then
  EMAIL_USER="$EMAIL"
fi

if [ -z "$DOMAIN" ]; then
  DOMAIN="${EMAIL#*@}"
fi

if [ -z "$SERVER" ]; then
  # Simple default guess; you can refine to use MX later if desired.
  # Default guess: mail.$domain. If --use-mx was specified prefer the first MX
  # record for SMTP-related checks.
  if [ "$USE_MX" -eq 1 ]; then
    _mx=$(dns_query MX "$DOMAIN" | awk '{print $2; exit}' || true)
    # Some MX answers can be the special '.' (null MX) — treat as "no MX".
    if [ -n "$_mx" ] && [ "$_mx" != "." ]; then
      SERVER="$_mx"
    else
      SERVER="mail.$DOMAIN"
    fi
  else
    SERVER="mail.$DOMAIN"
  fi
fi

if [ -z "$IMAP_SERVER" ]; then
  IMAP_SERVER="$SERVER"
fi

if [ -z "$POP_SERVER" ]; then
  POP_SERVER="$SERVER"
fi

if [ -z "$SMTP_SERVER" ]; then
  # If explicitly asked to use MX for SMTP, take most appropriate MX host
  if [ "$USE_MX" -eq 1 ]; then
    SMTP_SERVER="$SERVER"
  else
    SMTP_SERVER="$SERVER"
  fi
fi

if [ "$DO_AUTH" -eq 1 ] && [ -z "$EMAIL_PASS" ]; then
  read -srp "Enter password for $EMAIL_USER (will not echo): " EMAIL_PASS
  echo
fi

############################
# Main
############################
print_final_summary() {
  echo
  echo "${MAGENTA}${BOLD}==== RUN SUMMARY ====${RESET}"

  echo "${CYAN}${BOLD}Detected configuration:${RESET}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "Email:" "${EMAIL:-N/A}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "User:" "${EMAIL_USER:-N/A}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "Domain:" "${DOMAIN:-N/A}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "Server:" "${SERVER:-N/A}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "IMAP host:" "${IMAP_SERVER:-N/A}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "POP3 host:" "${POP_SERVER:-N/A}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "SMTP host:" "${SMTP_SERVER:-N/A}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "Timeout(s):" "${TCP_TIMEOUT:-N/A}"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "Auth tests:" "$( [ "${DO_AUTH:-0}" -eq 1 ] && echo enabled || echo disabled )"
  printf "  ${CYAN}%-14s${RESET} ${BOLD}%s${RESET}\n" "Show bodies:" "$( [ "${SHOW_BODY:-1}" -eq 1 ] && echo enabled || echo disabled )"

  echo
  echo "${CYAN}${BOLD}Detected tools:${RESET}"
  printf "  %s\n" "DNS: ${DNS_TOOL:-N/A}, TCP: ${NC_TOOL:-N/A}, TLS: ${OPENSSL_BIN:-N/A}, HTTP: ${CURL_BIN:-N/A}, timeout: ${TIMEOUT_BIN:-N/A}"

  echo
  # Ports summary
  if [ "${#SUMMARY_PORTS[@]}" -gt 0 ]; then
    echo "${BOLD}🔌 Ports & connectivity:${RESET}"
    for p in "${SUMMARY_PORTS[@]}"; do
      if printf "%s" "$p" | grep -q "NOT reachable"; then
        printf "  %s %s\n" "${CHECK_FAIL}" "$p"
      else
        printf "  %s %s\n" "${CHECK_OK}" "$p"
      fi
    done
    echo
  fi

  # TLS summary
  if [ "${#SUMMARY_TLS[@]}" -gt 0 ]; then
    echo "${BOLD}🔒 TLS handshakes & certs:${RESET}"
    for t in "${SUMMARY_TLS[@]}"; do
      if printf "%s" "$t" | grep -iq "FAILED\|error\|timed out"; then
        printf "  %s %s\n" "${CHECK_FAIL}" "$t"
      elif printf "%s" "$t" | grep -qi "verification may"; then
        printf "  %s %s\n" "${CHECK_WARN}" "$t"
      else
        printf "  %s %s\n" "${CHECK_OK}" "$t"
      fi
    done
    echo
  fi

  # Auth summary
  if [ "${#SUMMARY_AUTH[@]}" -gt 0 ]; then
    echo "${BOLD}🔑 Authentication attempts:${RESET}"
    for a in "${SUMMARY_AUTH[@]}"; do
      if printf "%s" "$a" | grep -qi "FAILED"; then
        printf "  %s %s\n" "${CHECK_FAIL}" "$a"
      else
        printf "  %s %s\n" "${CHECK_OK}" "$a"
      fi
    done
    echo
  fi

  if [ "${#SUMMARY_ISSUES[@]}" -eq 0 ]; then
    echo "${GREEN}No issues found.${RESET} ✅"
  else
    echo "${YELLOW}Issues detected (${#SUMMARY_ISSUES[@]}):${RESET}"
    local seen=()
    for i in "${SUMMARY_ISSUES[@]}"; do
      if printf "%s\n" "${seen[@]}" | grep -qxF -- "$i"; then
        continue
      fi
      seen+=("$i")
      printf "  - %s\n" "$i"
    done
  fi

  echo
  echo "Tip: inspect messages above for details, or rerun with --no-color to simplify parsing."

  # If JSON output was requested, also print a machine readable JSON summary
  if [ "${SUMMARY_FORMAT:-plain}" = "json" ]; then
    print_summary_json
  fi
}


json_escape() {
  # Minimal JSON escaping for strings: backslash, quote, newline, tab, carriage
  local s
  s="$1"
  s=${s//\\/\\\\}
  s=${s//"/\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

print_summary_json() {
  # Build a JSON object. Keep it simple and safe for typical strings.
  # Use printf to avoid shellwords issues.
  echo
  echo "{"
  printf '  "detected_configuration": {\n'
  printf '    "email": "%s",\n' "$(json_escape "${EMAIL:-}" )"
  printf '    "user": "%s",\n' "$(json_escape "${EMAIL_USER:-}" )"
  printf '    "domain": "%s",\n' "$(json_escape "${DOMAIN:-}" )"
  printf '    "server": "%s",\n' "$(json_escape "${SERVER:-}" )"
  printf '    "imap": "%s",\n' "$(json_escape "${IMAP_SERVER:-}" )"
  printf '    "pop3": "%s",\n' "$(json_escape "${POP_SERVER:-}" )"
  printf '    "smtp": "%s",\n' "$(json_escape "${SMTP_SERVER:-}" )"
  printf '    "timeout_seconds": %s,\n' "${TCP_TIMEOUT:-null}"
  printf '    "auth_tests": %s,\n' "$( [ "${DO_AUTH:-0}" -eq 1 ] && echo true || echo false )"
  printf '    "show_bodies": %s\n' "$( [ "${SHOW_BODY:-1}" -eq 1 ] && echo true || echo false )"
  printf '  },\n'

  printf '  "detected_tools": {\n'
  printf '    "dns": "%s",\n' "$(json_escape "${DNS_TOOL:-}" )"
  printf '    "tcp": "%s",\n' "$(json_escape "${NC_TOOL:-}" )"
  printf '    "tls": "%s",\n' "$(json_escape "${OPENSSL_BIN:-}" )"
  printf '    "http": "%s",\n' "$(json_escape "${CURL_BIN:-}" )"
  printf '    "timeout": "%s"\n' "$(json_escape "${TIMEOUT_BIN:-}" )"
  printf '  },\n'

  printf '  "ports": [\n'
  if [ "${#SUMMARY_PORTS[@]}" -gt 0 ]; then
    for i in "${!SUMMARY_PORTS[@]}"; do
      p="${SUMMARY_PORTS[$i]}"
      if [ "$i" -lt $(( ${#SUMMARY_PORTS[@]} - 1 )) ]; then
        printf '    "%s",\n' "$(json_escape "$p")"
      else
        printf '    "%s"\n' "$(json_escape "$p")"
      fi
    done
  fi
  printf '  ],\n'

  printf '  "tls": [\n'
  if [ "${#SUMMARY_TLS[@]}" -gt 0 ]; then
    for i in "${!SUMMARY_TLS[@]}"; do
      t="${SUMMARY_TLS[$i]}"
      if [ "$i" -lt $(( ${#SUMMARY_TLS[@]} - 1 )) ]; then
        printf '    "%s",\n' "$(json_escape "$t")"
      else
        printf '    "%s"\n' "$(json_escape "$t")"
      fi
    done
  fi
  printf '  ],\n'

  printf '  "auth": [\n'
  if [ "${#SUMMARY_AUTH[@]}" -gt 0 ]; then
    for i in "${!SUMMARY_AUTH[@]}"; do
      a="${SUMMARY_AUTH[$i]}"
      if [ "$i" -lt $(( ${#SUMMARY_AUTH[@]} - 1 )) ]; then
        printf '    "%s",\n' "$(json_escape "$a")"
      else
        printf '    "%s"\n' "$(json_escape "$a")"
      fi
    done
  fi
  printf '  ],\n'

  printf '  "issues": [\n'
  if [ "${#SUMMARY_ISSUES[@]}" -gt 0 ]; then
    for iidx in "${!SUMMARY_ISSUES[@]}"; do
      ii="${SUMMARY_ISSUES[$iidx]}"
      if [ "$iidx" -lt $(( ${#SUMMARY_ISSUES[@]} - 1 )) ]; then
        printf '    "%s",\n' "$(json_escape "$ii")"
      else
        printf '    "%s"\n' "$(json_escape "$ii")"
      fi
    done
  fi
  printf '  ]\n'

  echo "}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  # When SUMMARY_FORMAT=json we want to ensure stdout contains only the
  # machine-readable JSON. Temporarily redirect stdout to stderr and save the
  # original stdout on FD 3 so print_banner and other human output go to stderr.
  if [ "${SUMMARY_FORMAT:-plain}" = "json" ]; then
    exec 3>&1
    exec 1>&2
  fi

  print_banner

log_info "${BOLD}${CYAN}Email:${RESET}    ${BOLD}$EMAIL${RESET}"
log_info "${BOLD}${CYAN}User:${RESET}     ${BOLD}$EMAIL_USER${RESET}"
log_info "${BOLD}${CYAN}Domain:${RESET}   ${BOLD}$DOMAIN${RESET}"
log_info "${BOLD}${CYAN}Server:${RESET}   ${BOLD}$SERVER${RESET}"
log_info "${BOLD}${CYAN}IMAP:${RESET}     ${BOLD}$IMAP_SERVER${RESET}"
log_info "${BOLD}${CYAN}POP3:${RESET}     ${BOLD}$POP_SERVER${RESET}"
log_info "${BOLD}${CYAN}SMTP:${RESET}     ${BOLD}$SMTP_SERVER${RESET}"
if [ "$DO_AUTH" -eq 1 ]; then
  log_info "${BOLD}${CYAN}Auth:${RESET}     ${BOLD}enabled — password provided${RESET}"
else
  log_info "${BOLD}${CYAN}Auth:${RESET}     ${BOLD}connectivity only — no password${RESET}"
fi

# Notify user of default behaviour for plaintext legacy ports
if [ "${TEST_INSECURE_PORTS:-0}" -ne 1 ]; then
  log_info "Note: legacy plaintext ports (IMAP:143, POP3:110, SMTP:25) are skipped by default. Use --test-insecure-ports to include them."
fi

# If timeout helper isn't present, warn the user that some tests may block/hang
if [ -z "$TIMEOUT_BIN" ] && [ "$RUN_PORTS" -eq 1 ]; then
  log_warn "No 'timeout' command found on system — port/TLS/auth checks may hang. Install coreutils
  timeout or gtimeout on macOS for robust timeouts."
fi

[ "$RUN_DNS" -eq 1 ] && run_dns_tests "$DOMAIN"
[ "$RUN_AUTODISCOVER" -eq 1 ] && run_autodiscover_tests "$DOMAIN"
[ "$RUN_PORTS" -eq 1 ] && run_port_tests "$IMAP_SERVER" "$POP_SERVER" "$SMTP_SERVER"

echo
echo "${GREEN}${BOLD}All tests complete.${RESET} ${SPARK} ${CYAN}Review results above to identify any misconfigurations.${RESET}"
  # Print final summary or JSON-only output depending on requested format
  if [ "${SUMMARY_FORMAT:-plain}" = "json" ]; then
    # Prefer to emit JSON to the original stdout (saved on FD 3). If FD3 is
    # not writable for any reason, fall back to printing to the current stdout
    # so we don't produce a "Bad file descriptor" runtime error.
    if { true >&3; } 2>/dev/null; then
      print_summary_json >&3
      exec 3>&-
    else
      # FD3 not writable — fallback to writing JSON to current stdout
      print_summary_json
    fi
  else
    # Human-friendly summary to stdout
    print_final_summary
  fi
fi

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# MailProbe — email diagnostics and autodiscover tester (mailprobe.sh)
# Copyright (c) 2025 RandomArray
#
# Licensed under the MIT License. See https://opensource.org/licenses/MIT
#
# Author: Mike's AI sidekick 😎
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
log_info()  { echo -e "${CYAN}[i]${RESET} $*"; }
log_ok()    { echo -e "${CHECK_OK} ${GREEN}$*${RESET}"; }
log_warn()  { echo -e "${CHECK_WARN} ${YELLOW}$*${RESET}"; }
log_error() { echo -e "${CHECK_FAIL} ${RED}$*${RESET}" >&2; }

############################
# Banner
############################
print_banner() {
  # Use colored and concise banner header
  printf "%s\n" "${MAGENTA}${BOLD}MailProbe${RESET} by ${CYAN}RandomArray${RESET} — ${BOLD}MailProbe (open-source)${RESET}"
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
  --use-mx                 Prefer using MX host(s) for SMTP/server selection
  --show-body              Show HTTP response bodies for autodiscover/autoconfig (default ON)
  --no-show-body           Do not fetch or display HTTP response bodies
  --max-body-lines NUM     Maximum lines of HTTP body to print (default: 120)
      --no-autodiscover     Skip autodiscover/autoconfig HTTP tests
      --no-dns              Skip DNS tests
      --no-ports            Skip port/connectivity tests
      --no-color            Disable color output
  -h, --help                Show this help

Examples:
  # Provide password securely via environment (recommended):
  EMAIL_PASS=MySecret123 $(basename "$0") -e user@example.com -u user -p

  # Or pass password on command line (insecure; visible in process list):
  $(basename "$0") -e user@example.com -u user --password MySecret123 --use-mx
  $(basename "$0") -e user@example.com -S mail.example.com --no-autodiscover

EOF
}

############################
# Tool checks
############################
have_cmd() { command -v "$1" >/dev/null 2>&1; }

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
  if [ -n "$TIMEOUT_BIN" ]; then
    if "$TIMEOUT_BIN" "${timeout}s" bash -c "exec 3<>/dev/tcp/$host/$port" >/dev/null 2>&1; then
      exec 3>&-
      log_ok "[$label] TCP $host:$port reachable (via /dev/tcp)"
      return 0
    fi
  else
    if (exec 3<>"/dev/tcp/$host/$port") >/dev/null 2>&1; then
      exec 3>&-
      log_ok "[$label] TCP $host:$port reachable (via /dev/tcp)"
      return 0
    fi
  fi

  if [ -n "$NC_TOOL" ]; then
    # Try the most common netcat invocation first (with timeout)
    if "$NC_TOOL" -z -w "$timeout" "$host" "$port" >/dev/null 2>&1; then
      log_ok "[$label] TCP $host:$port reachable (via $NC_TOOL -z)"
      return 0
    fi

    # Some netcat variants are a bit different; try a minimal probe
    if "$NC_TOOL" -z "$host" "$port" >/dev/null 2>&1; then
      log_ok "[$label] TCP $host:$port reachable (via $NC_TOOL -z fallback)"
      return 0
    fi
  fi

  log_error "[$label] TCP $host:$port NOT reachable"
  return 1
}

############################
# TLS helpers
############################
OPENSSL_BIN="$(require_one_of 'TLS handshakes' openssl || echo "")"
BASE64_BIN="$(require_one_of 'base64' base64 || echo "")"
TIMEOUT_BIN="$(require_one_of 'timeout' timeout gtimeout || echo "")"

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
  if [ -n "$TIMEOUT_BIN" ]; then
    if ! out="$($TIMEOUT_BIN "${timeout}s" "${cmd[@]}" </dev/null 2>/dev/null)"; then
      log_error "[$label] TLS handshake FAILED on $host:$port (timeout or error)"
      return 1
    fi
  else
    if ! out="$("${cmd[@]}" </dev/null 2>/dev/null)"; then
      log_error "[$label] TLS handshake FAILED on $host:$port"
      return 1
    fi
  fi

  if echo "$out" | grep -qi "Verify return code: 0"; then
    log_ok "[$label] TLS cert verified OK on $host:$port"
  else
    log_warn "[$label] TLS handshake OK but certificate verification may have issues"
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
    if [ -n "$TIMEOUT_BIN" ]; then
      out=$(printf "%b" "$imap_cmd" | $TIMEOUT_BIN "${timeout}s" "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" -starttls imap 2>/dev/null || true)
    else
      out=$(printf "%b" "$imap_cmd" | "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" -starttls imap 2>/dev/null || true)
    fi
  else
    if [ -n "$TIMEOUT_BIN" ]; then
      out=$(printf "%b" "$imap_cmd" | $TIMEOUT_BIN "${timeout}s" "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" 2>/dev/null || true)
    else
      out=$(printf "%b" "$imap_cmd" | "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" 2>/dev/null || true)
    fi
  fi

  if echo "$out" | grep -qi "^a1 OK"; then
    log_ok "[$label] IMAP LOGIN succeeded for $EMAIL_USER"
  else
    log_error "[$label] IMAP LOGIN appears to have FAILED for $EMAIL_USER"
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
    if [ -n "$TIMEOUT_BIN" ]; then
      out=$(printf "%b" "$pop_cmd" | $TIMEOUT_BIN "${timeout}s" "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" -starttls pop3 2>/dev/null || true)
    else
      out=$(printf "%b" "$pop_cmd" | "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" -starttls pop3 2>/dev/null || true)
    fi
  else
    if [ -n "$TIMEOUT_BIN" ]; then
      out=$(printf "%b" "$pop_cmd" | $TIMEOUT_BIN "${timeout}s" "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" 2>/dev/null || true)
    else
      out=$(printf "%b" "$pop_cmd" | "$OPENSSL_BIN" s_client -crlf -quiet -connect "${host}:${port}" 2>/dev/null || true)
    fi
  fi

  if echo "$out" | grep -qi "+OK"; then
    log_ok "[$label] POP3 login returned +OK for $EMAIL_USER"
  else
    log_error "[$label] POP3 login appears to have FAILED for $EMAIL_USER"
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
    echo "$mx" | sed 's/^/  /'
  else
    log_warn "No MX records found for $domain"
  fi

  log_info "${BOLD}${MAGENTA}A/AAAA for $domain:${RESET}"
  local aaaa
  aaaa=$(dns_query A "$domain"; dns_query AAAA "$domain" || true)
  if [ -n "$aaaa" ]; then
    echo "$aaaa" | sed 's/^/  /'
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
    echo "$dmarc" | sed 's/^/  /'
  else
    log_warn "No DMARC record found"
  fi

  log_info "${BOLD}${MAGENTA}Autodiscover/Autoconfig hostnames:${RESET}"
  for host in "autodiscover.$domain" "autoconfig.$domain"; do
    local rec
    rec=$(dns_query A "$host"; dns_query CNAME "$host" || true)
    if [ -n "$rec" ]; then
      log_ok "${GREEN}$host resolves to:${RESET}"
      echo "$rec" | sed 's/^/  /'
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
      echo "$srvdata" | sed 's/^/  /'
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
      log_warn "Endpoint returned no HTTP status header: $u"
      echo "   Status: $status"
      code=""
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
  for port in 143 993; do
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
  for port in 110 995; do
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
  for port in 25 465 587; do
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
  if [ -n "$TIMEOUT_BIN" ]; then
    out=$(printf "%b" "$auth_cmd" | $TIMEOUT_BIN "${timeout}s" "${sargs[@]}" 2>/dev/null || true)
  else
    out=$(printf "%b" "$auth_cmd" | "${sargs[@]}" 2>/dev/null || true)
  fi

  if echo "$out" | grep -qiE "^235|Authentication successful"; then
    log_ok "[$label] SMTP AUTH succeeded for $EMAIL_USER"
  else
    log_error "[$label] SMTP AUTH appears to have FAILED for $EMAIL_USER"
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
      EMAIL_PASS="$2"; shift 2;;
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
    --no-color)
      NO_COLOR=1; USE_COLOR=0; shift;;
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
print_banner

log_info "${BOLD}${CYAN}Email:${RESET}    ${BOLD}$EMAIL${RESET}"
log_info "${BOLD}${CYAN}User:${RESET}     ${BOLD}$EMAIL_USER${RESET}"
log_info "${BOLD}${CYAN}Domain:${RESET}   ${BOLD}$DOMAIN${RESET}"
log_info "${BOLD}${CYAN}Server:${RESET}   ${BOLD}$SERVER${RESET}"
log_info "${BOLD}${CYAN}IMAP:${RESET}     ${BOLD}$IMAP_SERVER${RESET}"
log_info "${BOLD}${CYAN}POP3:${RESET}     ${BOLD}$POP_SERVER${RESET}"
log_info "${BOLD}${CYAN}SMTP:${RESET}     ${BOLD}$SMTP_SERVER${RESET}"
if [ "$DO_AUTH" -eq 1 ]; then
  log_info "Auth:     ${BOLD}enabled (password provided)${RESET}"
else
  log_info "Auth:     ${BOLD}connectivity only (no password)${RESET}"
fi

# If timeout helper isn't present, warn the user that some tests may block/hang
if [ -z "$TIMEOUT_BIN" ] && [ "$RUN_PORTS" -eq 1 ]; then
  log_warn "No 'timeout' command found on system — port/TLS/auth checks may hang. Install coreutils (timeout) or gtimeout on macOS for robust timeouts."
fi

[ "$RUN_DNS" -eq 1 ] && run_dns_tests "$DOMAIN"
[ "$RUN_AUTODISCOVER" -eq 1 ] && run_autodiscover_tests "$DOMAIN"
[ "$RUN_PORTS" -eq 1 ] && run_port_tests "$IMAP_SERVER" "$POP_SERVER" "$SMTP_SERVER"

echo
echo "${GREEN}${BOLD}All tests complete.${RESET} ${SPARK} ${CYAN}Review results above to identify any misconfigurations.${RESET}"
echo "Pro tip: tweak servers/ports and rerun to simulate different client setups. 🧪"

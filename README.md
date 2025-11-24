# MailProbe

**MailProbe** is a lightweight, comprehensive diagnostics toolkit for testing and validating email infrastructure.
Maintained by Mike Johanning <mikejohanning@gmail.com> (RandomArray)

This is the state of the context at this point in the conversation. The view of the workspace structure may be truncated. You can use tools to collect more context if needed.

- Email delivery
- Mail client configuration
- Authentication failures
- TLS certificate problems
- DNS configuration
- Autodiscover & autoconfig endpoints

MailProbe runs entirely from the command line and requires no installation—just a POSIX shell and common networking tools.

## ✨ Features

### 🔍 DNS Validation
- MX records
- SPF (TXT)
- DMARC
- A/AAAA
- SRV records (RFC6186)

### 📡 Port & Connectivity Tests
- IMAP: 143 / 993
- POP3: 110 / 995
- SMTP: 25 / 465 / 587
- Timeout-controlled TCP probing
- STARTTLS verification

### 🔐 TLS Analysis
- Certificate chain
- Issuer / Subject parsing
- Expiration date
- STARTTLS support detection

### 🔑 Optional Authentication Tests
- IMAP LOGIN
- POP3 USER/PASS
- SMTP AUTH LOGIN (Base64)

Authentication is optional and only enabled with `-p` or `--password`.

### 🌐 Autodiscover & Autoconfig Testing
- Microsoft autodiscover XML
- Mozilla autoconfig
- Optional HTTP body preview
- Status classification
- Redirect following

### ⚙️ Configurable Options
- MX-based server selection (`--use-mx`)
- Adjustable timeouts (`--timeout`)
- ANSI color control (`--no-color`)
- Body size limits (`--max-body-lines`)
- Optional skipping of test suites

## 🚀 Quick Start

```
chmod +x mailprobe.sh
./mailprobe.sh -e user@example.com
```

### With password prompt:

```
./mailprobe.sh -e user@example.com -p
```

### With password via environment (recommended):

```
EMAIL_PASS="MyPassword" ./mailprobe.sh -e user@example.com -p
```

### Use MX-host for SMTP:

```
./mailprobe.sh -e user@example.com --use-mx
```

## ⚙️ Installation (system-wide)

```
sudo cp mailprobe.sh /usr/local/bin/mailprobe
sudo chmod +x /usr/local/bin/mailprobe
```

Then run:

```
mailprobe -e user@example.com
```

## 🛡️ Requirements

MailProbe gracefully degrades based on available tools.
It makes use of:

- bash
- dig or host
- openssl
- nc / netcat / ncat
- curl or wget
- timeout / gtimeout
- base64

## 📄 License

Licensed under the MIT License. See `LICENSE` for details.

## 🧩 Shields.io Badges

```
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Shell](https://img.shields.io/badge/shell-bash-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
```

## 🤝 Contributing

Pull requests are always welcome.

## 🐛 Bug Reports

If MailProbe detects weird DNS, TLS errors, or inconsistencies across providers, open an issue and include:

- Command used
- Output snippet
- Server logs (if possible)

## ⭐ Why MailProbe?

Building and debugging email environments is hard.
MailProbe simplifies that by giving you **one clean, unified tool** that checks *everything that matters*.

# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- Initial project scaffolding and CI

## [1.1.0] - 2025-11-24

- Make JSON summary mode truly JSON-only on stdout; route human diagnostics to stderr.
- Add help example and README guidance for capturing JSON-only output (pipe to jq).
- Add CI check to validate JSON-only stdout and human diagnostics separation.
- Fixed FD3/file-descriptor handling and removed accidental closure in TCP probes to avoid "Bad file descriptor" errors.
- Improve print_summary_json to emit valid JSON (no trailing commas) and make JSON emission defensive.
- Add new CLI flag `--test-insecure-ports` to opt in to testing legacy plaintext ports (143/110/25); these are skipped by default.
- Add tests ensuring JSON-only behavior and the no-redirect scenario.


## [1.0.0] - 2025-11-23

- Initial public release — MailProbe single-file shell utility

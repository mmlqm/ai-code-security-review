# Changelog

All notable changes to this project are tracked here.

This project uses Conventional Commits for commit messages.

## Unreleased

### Added

- Built-in rules split into `scripts/rules_builtin.py`.
- `.auditignore` support.
- Incremental changed-file scanning with `--changed-files` and `--changed-files-from`.
- Colorized text output with `--color auto|always|never`.
- Fourteen additional built-in rules covering JWT none algorithms, MongoDB injection, mass assignment, SSTI, open redirects, XSS sinks, wildcard credentialed CORS, weak bcrypt rounds, public S3 ACLs, and framework default risks.
- Expanded test suite for scanner rules and engine features.

## 0.2.0 - 2026-07-10

### Added

- `.audit-code.toml` configuration loading.
- Custom TOML policy rules.
- Rule listing with built-in versus custom rule origins.
- Baseline writing and filtering.
- Inline suppressions with `audit-code: ignore` and `audit-code: ignore-next-line`.
- GitHub Actions annotation output.
- Finding fingerprints in JSON, Markdown, and SARIF properties.
- Configuration reference documentation.

## 0.1.0 - 2026-07-10

### Added

- Initial Codex skill package.
- Offline stdlib-only scanner.
- Text, JSON, Markdown, and SARIF output.
- CI workflow, tests, license, and repository formatting checks.

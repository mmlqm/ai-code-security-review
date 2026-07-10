# Changelog

All notable changes to this project are tracked here.

This project uses Conventional Commits for commit messages.

## Unreleased

### Added

- LLM deep-analysis workflow with seven review dimensions and structured report guidance.
- Agent metadata for Codex/OpenAI and Claude-oriented review workflows.
- Built-in rules split into `scripts/rules_builtin.py`.
- `.auditignore` support.
- Incremental changed-file scanning with `--changed-files` and `--changed-files-from`.
- Colorized text output with `--color auto|always|never`.
- Custom-rule `multiline` deprecation in favor of `anchors_cross_lines`.
- True multi-line custom-rule scanning with `scan_mode = "file"` and `scan_mode = "sliding_window"`.
- INFO findings and summary counts for lines skipped because they exceed the scanner line-length limit.
- Requirements inline-comment handling for dependency pin checks.
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

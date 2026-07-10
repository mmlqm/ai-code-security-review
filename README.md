# AI Code Security Review

Offline, stdlib-only security review for AI-generated or rapidly shipped code.

This repository packages a Codex skill and a deterministic local scanner for release gates. It is designed for the moment before code lands: catch hardcoded secrets, authorization placeholders, unsafe defaults, injection sinks, weak crypto, risky deployment settings, dependency hygiene gaps, and missing delivery safeguards without installing external scanners or calling network services.

## Why It Exists

AI-generated code often looks complete before it is safe to ship. This tool focuses on the failures that repeatedly slip through:

- Hardcoded credentials, tokens, private keys, and secret-like values.
- TODO/FIXME authorization placeholders and temporary bypasses.
- SQL, command, path traversal, SSRF, eval, and deserialization sinks.
- Disabled TLS/JWT validation, weak randomness, weak hashes, insecure cookies, and wide-open CORS.
- Docker and Kubernetes privilege risks.
- Unpinned dependencies, missing lockfiles, missing tests, missing CI, and committed `.env` files without examples.

The goal is not to replace Semgrep, CodeQL, or a mature SAST program. The goal is a fast, boring, offline gate that catches high-signal mistakes before release.

## Features

- Pure Python standard library. No pip install and no network access.
- Text, JSON, Markdown, and SARIF reports.
- CI-friendly exit codes with configurable severity thresholds.
- GitHub Actions annotations.
- Custom TOML policy rules for team-specific checks.
- `.auditignore` support for generated files and large repository hygiene.
- Incremental scans with explicit changed-file lists.
- Colorized terminal output for local use.
- Baseline support for legacy findings so new issues still fail the gate.
- Inline suppressions for reviewed false positives.
- Fingerprints for stable tracking across reports.
- Expanded AI-failure rules for JWT none algorithms, MongoDB injection, mass assignment, SSTI, open redirects, XSS sinks, weak bcrypt cost factors, public S3 ACLs, and risky framework defaults.
- Codex skill metadata and workflow guidance.

## Quick Start

Run a local review:

```bash
python scripts/audit_code.py .
```

Fail on high or critical findings:

```bash
python scripts/audit_code.py . --fail-on HIGH
```

Write SARIF for code scanning platforms:

```bash
python scripts/audit_code.py . --format sarif --output ai-code-security.sarif
```

Emit GitHub Actions annotations:

```bash
python scripts/audit_code.py . --github-annotations
```

Scan only changed files:

```bash
git diff --name-only origin/main...HEAD > changed.txt
python scripts/audit_code.py . --changed-files-from changed.txt --fail-on HIGH
```

Force color locally:

```bash
python scripts/audit_code.py . --color always
```

List active rules:

```bash
python scripts/audit_code.py . --list-rules
```

## Configuration

Generate a starter config:

```bash
python scripts/audit_code.py . --init-config
```

Example `.audit-code.toml`:

```toml
[settings]
fail_on = "HIGH"
include_tests = false
exclude = ["dist/**", "build/**", "generated/**"]

[[rules]]
id = "policy-no-legacy-auth"
title = "Legacy auth helper is disallowed"
severity = "HIGH"
category = "policy"
pattern = "\\blegacy_authenticate\\b"
remediation = "Use the central auth middleware."
extensions = [".py", ".js", ".ts"]
```

See [references/configuration.md](references/configuration.md) for custom rules, baselines, and suppressions.

Use `.auditignore` for generated or vendored paths:

```gitignore
dist/**
build/**
generated/**
*.sarif
```

## Baselines

Create a baseline for existing debt:

```bash
python scripts/audit_code.py . --fail-on none --write-baseline .audit-baseline.json
```

Then fail only on newly introduced findings:

```bash
python scripts/audit_code.py . --baseline .audit-baseline.json --fail-on HIGH
```

Do not auto-refresh baselines in CI. Update them deliberately in review.

## Inline Suppressions

Use suppressions only after checking the source context:

```python
return True  # fixture only audit-code: ignore auth-placeholder

# audit-code: ignore-next-line secret-generic-hardcoded
API_KEY = "fixture value"
```

Prefer rule-specific suppressions over broad `audit-code: ignore`.

## GitHub Actions

Minimal workflow:

```yaml
name: validate

on:
  push:
  pull_request:

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m unittest discover -s tests -p "test_*.py"
      - run: python scripts/audit_code.py . --format text --fail-on HIGH --github-annotations
```

## Codex Skill Layout

```text
ai-code-security-review/
├── SKILL.md
├── agents/openai.yaml
├── references/
│   ├── configuration.md
│   └── review-policy.md
└── scripts/
    ├── audit_code.py
    └── rules_builtin.py
```

Use the skill when asking Codex to perform release-readiness review, explain findings, add targeted tests, or wire the scanner into CI.

## Boundaries

This project is defensive and code-focused.

It does not perform live target scanning, reconnaissance, exploitation, password attacks, bypass generation, or network probing. When a workflow requires runtime security testing, use appropriate authorized testing tools outside this skill.

## Development

Run tests:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Run the scanner against itself:

```bash
python scripts/audit_code.py . --format text --fail-on HIGH
```

Validate the skill package:

```bash
python /path/to/quick_validate.py .
```

Use Conventional Commits:

```text
feat(scanner): add custom policy rules
fix(baseline): ignore selected baseline file during scans
docs(readme): explain CI annotations
```

## License

MIT. See [LICENSE](LICENSE).

---
name: ai-code-security-review
description: Offline defensive security review for AI-generated or rapidly produced application code before release. Use when Codex is asked to review a repository, pull request, generated code, CI gate, or file set for hardcoded secrets, authorization placeholders, injection sinks, weak crypto/TLS/JWT usage, unsafe deserialization, permissive CORS/CSRF/cookie settings, Docker/Kubernetes risks, dependency hygiene, missing tests, missing CI, custom team policy rules, baselines for existing findings, GitHub Actions annotations, or text, JSON, Markdown, and SARIF security reports. This skill is for code review and delivery gating only; it does not perform network reconnaissance, vulnerability scanning of live targets, exploitation, credential attacks, or bypass generation.
---

# AI Code Security Review

## Overview

Review application code before release using an offline, stdlib-only scanner plus manual triage. Prefer this skill for defensive review of code that is AI-generated, rushed, or headed into CI.

## Workflow

1. Identify the review scope: repository root, changed files, generated output folder, or a single file.
2. Run the bundled scanner from the skill directory:

```bash
python scripts/audit_code.py /path/to/repo --format markdown --fail-on HIGH
```

3. Inspect CRITICAL and HIGH findings in source before claiming they are real. Treat the scanner as a deterministic first pass, not final judgment.
4. When asked to fix issues, patch the smallest relevant code paths and add or update focused tests where the risk warrants it.
5. Report release blockers first, then non-blocking hardening items, then residual risk and any scan limitations.

## Scanner

Use `scripts/audit_code.py` for offline checks. It reads local files only and does not call network services or external scanners.

Common commands:

```bash
# Human-readable review
python scripts/audit_code.py /path/to/repo

# Markdown report for PR comments or release notes
python scripts/audit_code.py /path/to/repo --format markdown --output ai-code-security.md

# SARIF for code scanning platforms
python scripts/audit_code.py /path/to/repo --format sarif --output ai-code-security.sarif

# Report without failing CI
python scripts/audit_code.py /path/to/repo --fail-on none

# Include tests, examples, and fixtures when they are in release scope
python scripts/audit_code.py /path/to/repo --include-tests

# Generate a starter config with custom-rule examples
python scripts/audit_code.py /path/to/repo --init-config

# Use a baseline so only newly introduced findings fail the gate
python scripts/audit_code.py /path/to/repo --baseline .audit-baseline.json

# List active built-in and custom rules
python scripts/audit_code.py /path/to/repo --list-rules

# Add native GitHub Actions annotations
python scripts/audit_code.py /path/to/repo --github-annotations
```

Formats: `text`, `json`, `markdown`, `sarif`.

Fail thresholds: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `none`.

Configuration: use `.audit-code.toml` for custom rules, disabled rules, excludes, baseline paths, and default gate settings. Read `references/configuration.md` before creating or editing project config.

## Manual Triage

For each serious finding, verify:

- The file is part of deliverable application code, not a test fixture or inert example.
- The snippet is executable or configuration-effective in the target environment.
- The remediation matches the framework and coding style already present.
- Secret findings are redacted in user-facing output. Recommend rotation if a real secret was committed.
- Project-level findings such as missing tests, missing CI, or missing lockfiles are treated as delivery risk, not proof of a vulnerability.
- Suppress only reviewed false positives with `audit-code: ignore <rule-id>` or `audit-code: ignore-next-line <rule-id>`, and prefer baselines for legacy debt.

Read `references/review-policy.md` when you need severity guidance, report shape, or false-positive handling.

## Boundaries

Keep the work defensive and code-focused:

- Do not run reconnaissance, port scanning, live vulnerability probes, exploitation, password attacks, WAF bypass generation, or payload generation.
- Do not add network scanners or offensive test harnesses to this skill.
- When a user asks for live target testing, pivot to reviewing source code, configuration, CI artifacts, or a user-provided report.
- When a vulnerability is found in code, provide a concise explanation and concrete defensive patch guidance.

## Resources

- `scripts/audit_code.py`: Offline deterministic scanner and report renderer.
- `references/review-policy.md`: Triage and reporting guidance for release reviews.
- `references/configuration.md`: Config, custom rules, baseline, and suppression guidance.

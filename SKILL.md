---
name: ai-code-security-review
description: White-box AI-assisted security review for AI-generated or rapidly produced application code before release. Use when asked to review a repository, pull request, generated code, CI gate, or file set for hardcoded secrets, auth placeholders, injection sinks, weak crypto/TLS/JWT usage, unsafe deserialization, permissive CORS/CSRF/cookies, Docker/Kubernetes risks, dependency hygiene, missing tests/CI, custom TOML policy rules, .auditignore exclusions, incremental scans, baselines, GitHub Actions annotations, or text/JSON/Markdown/SARIF reports. Provides Claude/Codex review packs, agent metadata, report merging, and a seven-dimension source-evidence workflow. Defensive source/config/CI review only; no live-service testing.
---

# AI Code Security Review

## Overview

Review application code before release with a three-stage white-box workflow that works well in both Claude and Codex:

1. **Fast Gate** - `audit_code.py`: deterministic, zero-dependency scanner. Catches hardcoded secrets, obvious injection sinks, weak crypto, and misconfigurations quickly enough for every commit.

2. **AI Review Pack** - `ai_review_pack.py`: builds a Claude/Codex-ready source brief with scanner output, changed files, hotspots, redacted evidence, token estimates, and review prompts.

3. **Report Merge** - `ai_report.py`: merges scanner JSON and Claude/Codex JSON findings into stable Markdown, JSON, and PR-comment output.

```
pre-commit / CI -> audit_code.py -> scanner.json
                                      |
                                      v
PR / release review -> ai_review_pack.py -> Claude / Codex JSON
                                      |
                                      v
                               ai_report.py -> unified report
```

## Quick Start

### Fast Gate (always run first)

```bash
# Human-readable review
python scripts/audit_code.py /path/to/repo

# Fail on high or critical findings
python scripts/audit_code.py /path/to/repo --fail-on HIGH

# JSON for machine consumption
python scripts/audit_code.py /path/to/repo --format json --fail-on none
```

### AI-Assisted Deep Analysis (Claude / Codex)

Generate a model-ready review pack:

```bash
# Codex-oriented pack
python scripts/ai_review_pack.py /path/to/repo --agent codex --depth deep

# Claude-oriented pack
python scripts/ai_review_pack.py /path/to/repo --agent claude --depth deep

# PR/MR changed-file pack
python scripts/ai_review_pack.py /path/to/repo --changed-files-from changed.txt
```

The pack contains scanner output, redacted findings, security hotspots, changed
files, and a platform-specific prompt. It does not call any external AI service.
Ask Claude/Codex to return JSON matching `references/ai-output-schema.md`, then
merge scanner and AI findings:

```bash
python scripts/audit_code.py /path/to/repo --format json --fail-on none --output scanner.json
python scripts/ai_report.py /path/to/repo --scanner-report scanner.json --ai-findings ai-findings.json --output ai-code-security-report.md --pr-comment-output ai-code-security-pr-comment.md
```

### AI-Assisted Source Review (PR review / pre-release)

When the user requests a deep review, follow the workflow in `references/deep-analysis.md`:

1. **Run the scanner** - always first, for deterministic surface coverage
2. **Review across seven dimensions:**

   | Dimension | What it finds |
   |-----------|--------------|
   | Auth & Access Control | Bypassable gates, missing checks, token flaws, session fixation, JWT injection |
   | Data Flow & Injection | Tainted data from source to dangerous sink, second-order injection, ORM escape hatches |
   | Crypto & Secrets | Algorithm misuse, weak randomness, hardcoded keys, missing authentication on encryption |
   | Error Handling & Info Leak | Stack traces, debug endpoints, user enumeration, secrets in logs, timing side-channels |
   | Business Logic & Race | TOCTOU, workflow skips, negative value abuse, replay risks, idempotency gaps |
   | Supply Chain & Deployment | Docker/K8s privilege risks, CI secret leaks, unpinned dependencies, artifact integrity |
   | Architecture & Trust | Trust boundary violations, missing defense layers, implicit security assumptions |

3. **Merge and prioritize** - deduplicate across dimensions, cross-reference scanner findings
4. **Risk-chain synthesize** - combine related findings only when concrete evidence shows a higher-impact path
5. **Evidence verify** - for each HIGH/CRITICAL, try to disprove it using source evidence
6. **Report** - release blockers first, then review-required, then hardening

## Scanner Commands

```bash
# Basic scan
python scripts/audit_code.py /path/to/repo

# Markdown report for PR comments
python scripts/audit_code.py /path/to/repo --format markdown --output ai-code-security.md

# SARIF for code scanning platforms
python scripts/audit_code.py /path/to/repo --format sarif --output ai-code-security.sarif

# JSON for feeding into AI-assisted source review
python scripts/audit_code.py /path/to/repo --format json --fail-on none

# Report without failing CI
python scripts/audit_code.py /path/to/repo --fail-on none

# Include tests, examples, and fixtures
python scripts/audit_code.py /path/to/repo --include-tests

# Generate a starter config with custom-rule examples
python scripts/audit_code.py /path/to/repo --init-config

# Use a baseline so only newly introduced findings fail the gate
python scripts/audit_code.py /path/to/repo --baseline .audit-baseline.json

# List active built-in and custom rules
python scripts/audit_code.py /path/to/repo --list-rules

# Add native GitHub Actions annotations
python scripts/audit_code.py /path/to/repo --github-annotations

# Scan only files changed in a PR/MR
python scripts/audit_code.py /path/to/repo --changed-files-from changed.txt

# Force color for local terminal review
python scripts/audit_code.py /path/to/repo --color always

# Build a Claude/Codex review pack from scanner results
python scripts/ai_review_pack.py /path/to/repo --agent codex --depth deep

# Merge scanner JSON with Claude/Codex JSON findings
python scripts/ai_report.py /path/to/repo --scanner-report scanner.json --ai-findings ai-findings.json
```

Formats: `text`, `json`, `markdown`, `sarif`.

Fail thresholds: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `none`.

Configuration: use `.audit-code.toml` for custom rules, disabled rules, excludes, baseline paths, multi-line scan modes, and default gate settings. Copy `.audit-code.example.toml` for a ready-to-edit template. Use `.auditignore` for generated or vendored paths. Read `references/configuration.md` before creating or editing project config.

## Deep Analysis Prompt Templates

When invoking the LLM for deep review, use the dimension-specific prompts
defined in `references/deep-analysis.md`. Quick reference:

### Auth & Access Control
```
Read every auth middleware, guard, and decorator. For each protected route,
verify no path reaches the handler without passing through a gate. Check
for: different HTTP methods bypassing middleware, header-based auth confusion
(X-Forwarded-For, X-Original-URL), JWT algorithm/key injection, session
fixation, missing token rotation on privilege change.
```

### Data Flow & Injection
```
Trace every external input (query params, body, headers, file upload, DB
read, API response) to every dangerous sink (SQL execute, shell exec, eval,
file open, template render, deserialization, HTTP request). Check sanitization
at each step. Look for second-order paths: data stored now, used unsafely later.
```

### Crypto & Secrets
```
Find every encrypt/decrypt/sign/hash/random call. Verify algorithm, key size,
IV handling, mode, padding. Check key material sources. Search for secrets in:
variable names, config files, test fixtures, comments, commit messages.
```

### Error Handling & Info Leak
```
Find every try/catch, error middleware, and log statement. Check what
information reaches the user. Test for user enumeration via different
error messages or timing. Check debug/dev config cannot reach production.
```

### Business Logic & Race Conditions
```
Map every state-changing operation: input -> validation -> read -> decision
-> write. Look for gaps between decision and write where concurrent requests
could interleave. Check numeric inputs for boundary abuse. Verify idempotency
on payment/transfer operations.
```

### Supply Chain & Deployment
```
Read Dockerfiles, K8s manifests, CI workflows. Check for: privileged
containers, secrets in build args, default ServiceAccounts with RBAC,
pipeline execution of unreviewed code, unpinned external actions.
```

### Architecture & Trust
```
Map trust boundaries. For each boundary: what controls exist, what's
missing. Identify implicit assumptions the code makes about its callers.
Ask: what breaks if each component receives malicious input?
```

## Manual Triage

For each serious finding, verify:

- The file is part of deliverable application code, not a test fixture or inert example.
- The snippet is executable or configuration-effective in the target environment.
- The remediation matches the framework and coding style already present.
- Secret findings are redacted in user-facing output. Recommend rotation if a real secret was committed.
- Project-level findings such as missing tests, missing CI, or missing lockfiles are treated as delivery risk, not proof of a vulnerability.
- Suppress only reviewed false positives with `audit-code: ignore <rule-id>` or `audit-code: ignore-next-line <rule-id>`, and prefer baselines for legacy debt.

Read `references/review-policy.md` when you need severity guidance, report shape, or false-positive handling.

## Scanner Strengths To Use

- Same-file Python variable tracking catches dynamic SQL or shell command strings that are assigned before reaching `execute()` or subprocess sinks.
- High-entropy unknown-token detection catches custom credentials that do not match cloud-provider formats.
- YAML/TOML/properties unquoted secret detection catches common config leaks such as Helm values.
- AI review packs include adaptive review scope and rough token estimates before Claude/Codex deep analysis.
- Dimension 0 risk-chain synthesis in `references/deep-analysis.md` links related findings into a higher-impact path only when evidence supports escalation.

## Boundaries

Keep the work defensive and code-focused:

- Do not exercise live services or run network probing from this skill.
- Do not add network scanners, generated request traffic, or non-defensive harnesses to this skill.
- When a user asks for testing against a running service, pivot to reviewing source code, configuration, CI artifacts, or a user-provided report.
- When a vulnerability is found in code, provide a concise explanation and concrete defensive patch guidance.

## Resources

| Resource | Purpose |
|----------|---------|
| `scripts/ai_review_pack.py` | Claude/Codex AI-assisted review pack generator |
| `scripts/ai_report.py` | Merge scanner and Claude/Codex JSON findings into final reports |
| `scripts/audit_code.py` | Deterministic fast-gate scanner, config loader, report renderer |
| `scripts/rules_builtin.py` | 52 built-in detection rules |
| `references/ai-output-schema.md` | JSON schema for AI findings and chain synthesis output |
| `.github/workflows/ai-security-review.yml` | Optional artifact workflow for SARIF, review packs, and reports |
| `.audit-code.example.toml` | Ready-to-edit scanner and policy configuration template |
| `.pre-commit-hooks.yaml` | Pre-commit hook metadata |
| `references/deep-analysis.md` | Full AI-assisted source review methodology with 7 dimension prompts |
| `references/review-policy.md` | Triage and reporting guidance |
| `references/configuration.md` | Config, custom rules, baseline, and suppression guidance |
| `agents/claude.yaml` | Claude-specific agent configuration |
| `agents/openai.yaml` | Codex/OpenAI agent configuration |

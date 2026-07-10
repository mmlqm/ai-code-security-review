# AI Code Security Review

White-box AI code security review for Claude and Codex: an offline scanner, evidence-based review packs, and deterministic report merging for release-ready code.

This repository packages a Codex skill, Claude/Codex agent metadata, and three local tools: `audit_code.py` for deterministic scanning, `ai_review_pack.py` for source-evidence review packs, and `ai_report.py` for merging scanner and AI JSON findings into release reports. It is designed for the moment before code lands: catch hardcoded secrets, authorization placeholders, unsafe defaults, injection sinks, weak crypto, risky deployment settings, dependency hygiene gaps, and missing delivery safeguards without installing external scanners or calling network services. Then hand a compact, redacted review pack to Claude or Codex so AI assistance stays grounded in source code, configuration, CI, manifests, and dependency evidence.

## Why It Exists

AI-generated code often looks complete before it is safe to ship. This tool focuses on the failures that repeatedly slip through:

- Hardcoded credentials, tokens, private keys, and secret-like values.
- TODO/FIXME authorization placeholders and temporary bypasses.
- SQL, command, path traversal, SSRF, eval, and deserialization sinks.
- Disabled TLS/JWT validation, weak randomness, weak hashes, insecure cookies, and wide-open CORS.
- Docker and Kubernetes privilege risks.
- Unpinned dependencies, missing lockfiles, missing tests, missing CI, and committed `.env` files without examples.

The goal is not to replace Semgrep, CodeQL, or a mature SAST program. The goal is a fast, boring, offline gate that catches high-signal mistakes before release.

### White-Box Review Workflow

```
1. Fast Gate          audit_code.py
   Deterministic stdlib scanner for every commit and CI gate.

2. AI Review Pack     ai_review_pack.py
   Claude/Codex-ready source brief with scanner output, hotspots,
   changed files, token estimates, and review instructions.

3. Report Merge       ai_report.py
   Normalize scanner + AI findings into Markdown, JSON, PR comments,
   and release-ready evidence.
```

Read `references/deep-analysis.md` for the full AI-assisted source review methodology.

### What Makes It Different

- **Local-first and deterministic** - the scanner uses only the Python standard library and does not call external services.
- **Claude/Codex-ready** - review packs include platform-specific prompts, token estimates, redacted findings, and changed-file context.
- **Configurable for real teams** - `.audit-code.toml`, `.auditignore`, baselines, suppressions, and custom rules make it practical for older repositories.
- **Mergeable AI output** - Claude/Codex findings use a JSON schema that can be merged into stable reports and PR comments.
- **White-box boundary** - reviews stay on source code, configuration, CI, manifests, dependencies, and user-provided evidence.

### Claude/Codex AI-Assisted Review

Generate a review pack for Codex:

```bash
python scripts/ai_review_pack.py . --agent codex --depth deep --output ai-code-review-pack.md
```

Generate a review pack for Claude:

```bash
python scripts/ai_review_pack.py . --agent claude --depth deep --output ai-code-review-pack.md
```

For PR/MR review, include only changed files:

```bash
git diff --name-only origin/main...HEAD > changed.txt
python scripts/ai_review_pack.py . --agent codex --changed-files-from changed.txt
```

The pack includes scanner output, redacted findings, security-sensitive file hotspots, and a platform-specific prompt. It does not call Claude, Codex, OpenAI, Anthropic, or any network service by itself.

## Features

- **Fast gate scanner** — Pure Python standard library. No pip install and no network access.
- **AI-assisted source review** — Seven-dimension review (auth, dataflow, crypto, info-leak, business-logic, supply-chain, architecture) with structured prompt templates for Claude and Codex.
- **AI review pack generator** — `scripts/ai_review_pack.py` creates Claude/Codex-ready Markdown from local scanner results.
- **AI report merger** — `scripts/ai_report.py` merges scanner JSON and Claude/Codex JSON findings into final Markdown, normalized JSON, and PR-comment summaries.
- **Lightweight variable tracking** — Same-file Python tracking catches dynamic SQL or shell command strings that are assigned before reaching sinks.
- **Unknown token detection** — High-entropy strings and unquoted YAML/TOML/properties secrets are flagged for review.
- **Risk-chain synthesis** — Deep analysis includes a Dimension 0 merge pass that links related lower-severity findings into higher-impact paths when evidence supports it.
- **Context-aware AI packs** — Review packs include rough token estimates and adaptive dimension guidance so Claude/Codex spend attention where the repository has signals.
- Text, JSON, Markdown, and SARIF reports.
- CI-friendly exit codes with configurable severity thresholds.
- GitHub Actions annotations.
- Custom TOML policy rules for team-specific checks.
- Example configuration in `.audit-code.example.toml`.
- `.auditignore` support for generated files and large repository hygiene.
- Incremental scans with explicit changed-file lists.
- Colorized terminal output for local use.
- True custom-rule multi-line scanning with `scan_mode = "file"` or `scan_mode = "sliding_window"`.
- Explicit scan-limitation reporting for skipped long lines.
- Baseline support for legacy findings so new issues still fail the gate.
- Inline suppressions for reviewed false positives.
- Fingerprints for stable tracking across reports.
- Expanded AI-failure rules for JWT none algorithms, MongoDB injection, mass assignment, SSTI, open redirects, XSS sinks, weak bcrypt cost factors, public S3 ACLs, and risky framework defaults.
- Codex skill metadata and workflow guidance.
- Pre-commit hook metadata in `.pre-commit-hooks.yaml`.

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

Build an AI-assisted review pack:

```bash
python scripts/ai_review_pack.py . --agent codex --depth deep
```

Merge scanner output with Claude/Codex JSON findings:

```bash
python scripts/audit_code.py . --format json --fail-on none --output scanner.json
python scripts/ai_report.py . --scanner-report scanner.json --ai-findings ai-findings.json \
  --output ai-code-security-report.md --pr-comment-output ai-code-security-pr-comment.md
```

Use as a pre-commit hook:

```yaml
repos:
  - repo: https://github.com/mmlqm/ai-code-security-review
    rev: main
    hooks:
      - id: ai-code-security-review
```

## Configuration

Generate a starter config:

```bash
python scripts/audit_code.py . --init-config
```

Or copy and edit the checked-in example:

```bash
cp .audit-code.example.toml .audit-code.toml
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

Custom rules can stay line-oriented or opt into multi-line scanning:

```toml
[[rules]]
id = "policy-cross-line-template"
title = "Cross-line unsafe construct"
severity = "HIGH"
category = "policy"
pattern = "BEGIN_UNSAFE\\s+END_UNSAFE"
remediation = "Remove the cross-line unsafe construct."
scan_mode = "sliding_window"
window_lines = 3
```

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

For a fuller review workflow, see `.github/workflows/ai-security-review.yml`. It creates scanner JSON, SARIF, a Claude/Codex review pack, a scanner-only final report, and uploadable artifacts. After Claude/Codex produces JSON matching `references/ai-output-schema.md`, run `scripts/ai_report.py` again with `--ai-findings`.

## Codex Skill Layout

```text
ai-code-security-review/
├── SKILL.md                         # Skill entry point + deep analysis workflow
├── agents/
│   ├── claude.yaml                  # Claude agent system prompt + tool config
│   └── openai.yaml                  # Codex / OpenAI agent configuration
├── references/
│   ├── configuration.md             # TOML config, custom rules, baselines
│   ├── deep-analysis.md             # AI-assisted source review methodology (7 dimensions)
│   ├── ai-output-schema.md          # Claude/Codex JSON schema for report merging
│   └── review-policy.md             # Severity guidance + triage rules
├── scripts/
│   ├── ai_review_pack.py            # Claude/Codex AI-assisted review pack generator
│   ├── ai_report.py                 # Merge scanner + AI findings into final reports
│   ├── audit_code.py                # Deterministic fast-gate scanner engine
│   └── rules_builtin.py             # 52 built-in detection rule catalog
└── tests/
    ├── test_ai_report.py            # AI report merge tests
    ├── test_ai_review_pack.py       # AI review pack tests
    ├── test_audit_code.py           # Scanner feature tests
    ├── test_engine_features.py      # Engine feature tests
    └── test_rules.py                # Rule coverage tests
```

Use the skill when asking Codex to perform release-readiness review, explain findings, add targeted tests, or wire the scanner into CI.

## Boundaries

This project is defensive and code-focused.

It only reviews provided source code, configuration, CI files, lockfiles, manifests, and user-provided reports. It does not exercise live services, perform network probing, or generate request traffic.

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

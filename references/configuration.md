# Configuration

Use `.audit-code.toml` at the repository root when a team needs policy rules or stable CI behavior beyond the built-in checks.

## Starter Config

Run:

```bash
python scripts/audit_code.py . --init-config
```

Or copy the checked-in example:

```bash
cp .audit-code.example.toml .audit-code.toml
```

Important settings:

- `fail_on`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `none`.
- `include_tests`: scan tests, fixtures, and examples when true.
- `max_file_size`: skip larger files.
- `disabled_rules`: rule ids to turn off.
- `exclude`: glob patterns such as `generated/**`.
- `baseline`: path to a JSON baseline file.

High-entropy token detection is intentionally conservative and low-confidence.
If a repository stores many benign generated identifiers, disable
`secret-high-entropy-string` in `.audit-code.toml` after review:

```toml
[settings]
disabled_rules = ["secret-high-entropy-string"]
```

## Audit Ignore

Use `.auditignore` for generated, vendored, or release-output paths that should never be scanned:

```gitignore
dist/**
build/**
coverage/**
generated/**
*.sarif
```

The syntax is simple glob matching. Blank lines and `#` comments are ignored. Negated patterns are ignored for now.

## Incremental Scans

For PR/MR workflows, pass changed files explicitly:

```bash
git diff --name-only origin/main...HEAD > changed.txt
python scripts/audit_code.py . --changed-files-from changed.txt --fail-on HIGH
```

Or pass paths directly:

```bash
python scripts/audit_code.py . --changed-files app/auth.py web/server.ts
```

Project-level delivery checks still run. Use a baseline when existing project-level debt should not fail new changes.

The same changed-file list can drive an AI-assisted Claude/Codex review pack:

```bash
python scripts/ai_review_pack.py . --agent codex --changed-files-from changed.txt
python scripts/ai_review_pack.py . --agent claude --changed-files-from changed.txt
```

The pack keeps configuration local: scanner settings come from `.audit-code.toml`,
generated artifacts are excluded through `.auditignore`, and the resulting
Markdown is intended to be copied into the reviewing agent.

## Custom Rules

Add `[[rules]]` blocks for team policy checks:

```toml
[[rules]]
id = "policy-no-legacy-auth"
title = "Legacy auth helper is disallowed"
severity = "HIGH"
category = "policy"
pattern = "\\blegacy_authenticate\\b"
remediation = "Use the central auth middleware."
extensions = [".py", ".js", ".ts"]
scan_comments = false
confidence = "high"
```

Required fields: `id`, `title`, `severity`, `category`, `pattern`, `remediation`.

Optional fields: `extensions`, `filenames`, `scan_comments`, `sensitive_boost`, `ignore_case`, `anchors_cross_lines`, `dotall`, `scan_mode`, `window_lines`, `confidence`, `cwe`.

Use `anchors_cross_lines = true` when `^` and `$` anchors should apply to each line in a whole-file rule. The older `multiline = true` name is deprecated and maps to `anchors_cross_lines` for compatibility.

Use `scan_mode` for actual multi-line content matching:

```toml
[[rules]]
id = "policy-cross-line-template"
title = "Cross-line template construction"
severity = "HIGH"
category = "policy"
pattern = "BEGIN_UNSAFE\\s+END_UNSAFE"
remediation = "Avoid building this construct across lines."
scan_mode = "sliding_window"
window_lines = 3
```

Supported scan modes:

- `line`: default, fastest, scans one line at a time.
- `sliding_window`: scans overlapping windows of `window_lines`.
- `file`: scans the full file content.

Use `dotall = true` only when `.` should match newlines.

Keep custom rules narrow. Prefer a clear policy rule that catches one local risk over a broad expression that floods CI.

Built-in engine-only rules such as `sql-python-variable-track` and
`shell-python-variable-track` use same-file variable tracking rather than a
custom regular expression. They can be disabled like any other rule, but custom
rules cannot currently define new variable-tracking behavior.

## Suppressions

Use suppressions only after source review:

```python
return True  # test fixture only audit-code: ignore auth-placeholder

# audit-code: ignore-next-line secret-generic-hardcoded
API_KEY = "fixture value"
```

Use `audit-code: ignore` with a rule id whenever possible. Bare `audit-code: ignore` suppresses all findings on that line and should be rare.

## Baselines

Create a baseline for existing debt:

```bash
python scripts/audit_code.py . --fail-on none --write-baseline .audit-baseline.json
```

Then gate only new findings:

```bash
python scripts/audit_code.py . --baseline .audit-baseline.json --fail-on HIGH
```

Refresh baselines deliberately in code review. Do not auto-update them in CI.

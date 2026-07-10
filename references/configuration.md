# Configuration

Use `.audit-code.toml` at the repository root when a team needs policy rules or stable CI behavior beyond the built-in checks.

## Starter Config

Run:

```bash
python scripts/audit_code.py . --init-config
```

Important settings:

- `fail_on`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `none`.
- `include_tests`: scan tests, fixtures, and examples when true.
- `max_file_size`: skip larger files.
- `disabled_rules`: rule ids to turn off.
- `exclude`: glob patterns such as `generated/**`.
- `baseline`: path to a JSON baseline file.

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

Optional fields: `extensions`, `filenames`, `scan_comments`, `sensitive_boost`, `ignore_case`, `multiline`, `confidence`, `cwe`.

Keep custom rules narrow. Prefer a clear policy rule that catches one local risk over a broad expression that floods CI.

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

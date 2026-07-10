# Contributing

Thanks for helping improve AI Code Security Review.

## Development Loop

Run these before opening a pull request:

```bash
python -m unittest discover -s tests -p "test_*.py"
python scripts/audit_code.py . --format text --fail-on HIGH
python scripts/audit_code.py . --list-rules
```

If you edit skill metadata, also run the Codex skill validator:

```bash
python /path/to/quick_validate.py .
```

## Commit Format

Use Conventional Commits:

```text
feat(scanner): add custom policy rules
fix(baseline): ignore selected baseline file during scans
docs(config): document suppressions
test(scanner): cover github annotations
ci(validate): enforce commit format
```

Allowed types:

```text
feat, fix, docs, test, ci, chore, refactor, perf, build, style, revert
```

## Rule Changes

Good rules are narrow and explainable.

For a new built-in rule, include:

- A clear rule id.
- Severity and category.
- At least one positive test.
- At least one non-match or false-positive consideration when relevant.
- A remediation message that tells users what to do next.

Avoid broad patterns that create noisy CI failures. Prefer custom `.audit-code.toml` rules for team-specific policy.

## Suppressions And Baselines

Do not add suppressions or baselines to hide unknown issues. A suppression should include a short source-code rationale, and a baseline should be reviewed like any other release-risk artifact.

## Security Boundary

Keep this project offline and defensive. Do not add live-service testing or network activity features.

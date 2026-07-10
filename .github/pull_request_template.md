## Summary

- 

## Validation

- [ ] `python -m unittest discover -s tests -p "test_*.py"`
- [ ] `python scripts/audit_code.py . --format text --fail-on HIGH`
- [ ] `python scripts/audit_code.py . --list-rules`

## Security And Release Notes

- [ ] No secrets, tokens, credentials, or generated caches are committed.
- [ ] New findings are intentional or covered by tests.
- [ ] Config, baseline, or suppression changes include a short rationale.
- [ ] User-facing behavior is documented in `SKILL.md` or `references/`.

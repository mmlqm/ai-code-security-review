# Review Policy

Use this reference when turning scanner output into a release review.

## Severity

- CRITICAL: committed private keys, cloud credentials, or defects that can directly expose production systems or user data. Block release and recommend rotation for real secrets.
- HIGH: authorization bypasses, dynamic SQL or command execution, disabled signature/TLS validation, unsafe deserialization, or privileged deployment defaults. Block release unless there is a documented compensating control.
- MEDIUM: generated placeholders in sensitive paths, broad CORS/session weaknesses, missing CSRF protections, weak randomness, or risky defaults. Require owner review and prefer fixing before release.
- LOW: dependency pinning, lockfile, CI, and test hygiene. Track as delivery hardening unless combined with higher-risk evidence.
- INFO: context useful for reviewers but not a release blocker on its own.

## Report Shape

Lead with release blockers. For each blocker include:

- Location.
- Rule or risk category.
- Why it matters in this codebase.
- Concrete remediation.
- Whether a test or CI check should be added.

Then include non-blocking hardening items and any limitations such as skipped generated files, binary files, large files, or tests excluded by default.

## False Positive Handling

Do not delete findings casually. Mark a finding as likely false positive only when the source context proves one of these:

- The file is not shipped or executed.
- The value is a documented dummy fixture and tests/examples are outside the review scope.
- The suspicious pattern is part of a scanner rule, documentation snippet, or inert string.
- A framework-level guard prevents the risky path and the guard is covered by tests.

When in doubt, keep the item as "needs owner review" instead of clearing it.

## Secret Handling

Never repeat full secrets in reports or comments. If a real credential appears committed, recommend removal from history where appropriate and rotation through the owning provider. Treat screenshots, logs, and CI artifacts as potential secondary exposure.

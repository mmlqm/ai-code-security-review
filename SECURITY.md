# Security Policy

## Supported Scope

This project performs offline defensive code review and CI delivery gating.

Supported reports include:

- False negatives or false positives in local source scanning.
- Secret redaction issues in reports.
- SARIF or CI output problems.
- Unsafe behavior in the scanner itself.
- Packaging or skill metadata issues.

Out of scope:

- Live target scanning.
- Exploit development.
- Credential attacks.
- Bypass generation.
- Reconnaissance workflows.

## Reporting

Do not open a public issue with real secrets, private code, or exploit details.

If a finding involves sensitive material, report only:

- A short description of the issue.
- The affected file or feature area.
- A minimal synthetic reproduction when possible.
- Whether the issue can expose secrets in output.

If no private channel is configured for this repository, create a minimal public issue without sensitive data and request a maintainer contact path.

## Secret Handling

If a real token, password, private key, or cloud credential was committed or pasted into a workflow, rotate it immediately. Removing it from a later commit is not enough.

The scanner redacts common secret assignments in reports, but it cannot guarantee that every organization-specific token format is masked.

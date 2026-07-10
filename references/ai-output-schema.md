# AI Output Schema

Ask Claude or Codex to return JSON when a deterministic merge/report step is
needed. The output can contain `findings`, `chains`, or both.

```json
{
  "findings": [
    {
      "dimension": "auth|dataflow|crypto|info-leak|business-logic|supply-chain|architecture",
      "title": "Short finding title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": "high|medium|low",
      "location": "path/to/file.py:123",
      "description": "What is wrong and why it matters",
      "risk_path": "Code-evidence path showing how the weakness could matter",
      "impact": "What could happen if this is real",
      "remediation": "Specific code or configuration change",
      "test_recommendation": "Regression test to add",
      "cwe": "CWE-xxx"
    }
  ],
  "chains": [
    {
      "dimension": "chain-synthesis",
      "title": "Combined risk path",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "confidence": "high|medium|low",
      "linked_findings": ["scanner-rule-id", "path/to/file.py:123"],
      "location": "primary/path.py:123",
      "description": "How the linked findings combine",
      "impact": "Combined impact",
      "remediation": "Root fix that breaks the chain",
      "test_recommendation": "Regression test for the chain"
    }
  ]
}
```

Merge with scanner output:

```bash
python scripts/audit_code.py . --format json --fail-on none --output scanner.json
python scripts/ai_report.py . --scanner-report scanner.json --ai-findings ai-findings.json \
  --output ai-code-security-report.md --pr-comment-output ai-code-security-pr-comment.md
```

Keep real credentials out of AI output. If a real credential is found, describe
the type and location only, then require rotation.

This schema is for white-box source review. Do not include live-service test
steps, network activity, or generated request data.

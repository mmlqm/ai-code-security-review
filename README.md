<p align="center">
  <h1 align="center">AI Code Security Review</h1>
  <p align="center">
    <strong>White-box audit engine for the AI era.</strong><br>
    Deterministic scanner → AI deep reasoning → mergeable evidence.<br>
    Built for Claude &amp; Codex. Zero dependencies. Ships in CI.
  </p>
</p>

<p align="center">
  <a href="https://github.com/mmlqm/ai-code-security-review/actions"><img src="https://img.shields.io/badge/tests-55%2F55%20passing-brightgreen" alt="Tests"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/python-3.10%2B-3670A0?logo=python" alt="Python"></a>
  <a href="#"><img src="https://img.shields.io/badge/dependencies-zero-success" alt="Dependencies"></a>
  <a href="#"><img src="https://img.shields.io/badge/rules-52%20built--in-informational" alt="Rules"></a>
</p>

---

## Philosophy

Most SAST tools are either **fast and shallow** (regex linters) or **deep and slow**
(Semgrep, CodeQL — powerful but heavy, complex to configure, and blind to intent).

AI-generated code introduces a new failure mode: it *looks* complete but ships with
**placeholder auth, hardcoded secrets masquerading as config, and injection sinks
hidden behind innocent variable names.** Traditional tools miss these because they
pattern-match in isolation. LLMs catch them but hallucinate without grounding.

This project splits the difference: **a deterministic scanner for the things
machines are good at (pattern matching at scale), and structured evidence packs
for the things LLMs are good at (cross-file reasoning, intent inference, and
attack-chain synthesis).** Neither replaces the other — they compose.

```
                    ┌──────────────────────────┐
   pre-commit       │  audit_code.py           │  < 100ms
   every change ──▶ │  deterministic fast-gate  │  zero network
                    │  52 rules, same-file      │
                    │  taint tracking, entropy   │
                    │  detection, ReDoS-safe     │
                    └────────────┬─────────────┘
                                 │ findings.json
                                 ▼
                    ┌──────────────────────────┐
   PR review        │  ai_review_pack.py        │  local generation
   pre-release ───▶ │  Claude / Codex brief     │  no API calls
                    │  hotspots + prompts +      │
                    │  token budget + schema     │
                    └────────────┬─────────────┘
                                 │ review-pack.md
                                 ▼
                    ┌──────────────────────────┐
   AI reasoning     │  Claude or Codex          │  7 dimensions
   deep audit ────▶ │  cross-file data flow,    │  chain synthesis
                    │  auth-gate verification,   │  adversarial verify
                    │  business logic, trust     │
                    │  boundary mapping          │
                    └────────────┬─────────────┘
                                 │ ai-findings.json
                                 ▼
                    ┌──────────────────────────┐
   release gate     │  ai_report.py             │  deterministic merge
   final report ──▶ │  scanner + AI findings    │  Markdown / JSON / PR
                    │  deduped, prioritized,     │
                    │  evidence-linked           │
                    └──────────────────────────┘
```

## What It Catches

| Class | Scanner (deterministic) | AI Deep Review (LLM) |
|---|---|---|
| **Secrets** | AWS, GitHub PAT, GitLab, Slack, Stripe, OpenAI, Anthropic, JWT, private keys, high-entropy strings, YAML unquoted | Key rotation urgency, exposure path through logs/errors/CI artifacts |
| **Auth** | Placeholder bypasses, missing JWT validation, default session secrets, Django `ALLOWED_HOSTS=*` | Gate bypass via header injection, algorithm confusion, multi-tenant isolation breaks |
| **Injection** | SQL concatenation, `shell=True`, `eval()`, SSTI, pickle deserialization, MongoDB `$where` | Taint flow through 3+ functions, second-order injection, ORM escape-hatch misuse |
| **Data Flow** | Same-file variable tracking (SQL, shell, path traversal, SSRF) | Cross-file trace from HTTP entry point to dangerous sink |
| **Crypto** | MD5/SHA1 in auth context, `Math.random()` for tokens, `bcrypt(4)`, ECB mode | Missing MAC on encryption, non-constant-time comparison, key material lifecycle |
| **Supply Chain** | Unpinned Docker images, `curl \| sh`, missing lockfiles, `chmod 777` | CI secret exfiltration vectors, unpinned GitHub Actions, artifact integrity |
| **Config** | Debug mode enabled, wildcard CORS with credentials, insecure cookies, CSRF disabled | Trust boundary violations, missing defense-in-depth layers |

## Quick Start

```bash
# Clone and run — no pip install, no API keys, no network
git clone https://github.com/mmlqm/ai-code-security-review.git
python scripts/audit_code.py /path/to/your/repo --fail-on HIGH
```

```bash
# Generate an AI review pack for Claude or Codex
python scripts/ai_review_pack.py . --agent claude --depth deep

# Merge scanner + AI findings into a release report
python scripts/ai_report.py . --scanner-report scanner.json \
  --ai-findings ai-findings.json --output release-report.md
```

## Design Decisions

### Why zero dependencies

No `pip install`, no `npm`, no Docker. The scanner uses only the Python standard
library so it runs in **any CI runner, pre-commit hook, or air-gapped environment**
without a build step. This is a feature, not a limitation.

### Why a scanner AND an LLM

The scanner is fast, deterministic, and never hallucinates — but it's blind to
semantics. The LLM understands intent and can trace data across files — but it's
slow, non-deterministic, and can miss things a regex would catch. Running both
and merging results gives you **breadth from the machine and depth from the model.**

### Why evidence packs instead of API calls

`ai_review_pack.py` does not call Claude, Codex, or any API. It produces a
self-contained Markdown file with redacted scanner output, file hotspots, a
platform-specific prompt, and a token budget estimate. **You control when and
how the AI sees your code.** No source leaves your machine until you paste it.

### Why ReDoS protection on custom rules

`.audit-code.toml` custom rules let teams encode policy as regex. Without
guarding, a well-intentioned rule like `(a+)+b` can hang CI indefinitely.
The built-in complexity estimator and `safe_compile` wrapper block these
at config-load time, before they reach the scan loop.

## Architecture

```
scripts/
├── audit_code.py           Engine: 52 built-in rules, same-file taint tracking,
│                             entropy detection, multi-line scan modes, SARIF output
├── rules_builtin.py         Rule catalog: secrets, auth, injection, crypto,
│                             deployment, supply-chain, XSS, config
├── ai_review_pack.py        Evidence pack generator: scanner JSON → Claude/Codex
│                             Markdown brief with hotspots, prompts, token budget
├── ai_report.py             Report merger: scanner + AI JSON → Markdown, normalized
│                             JSON, PR comment summary, release-ready evidence
├── redact.py                Enhanced redaction: 15+ token formats, entropy-based
│                             unknown token detection, YAML unquoted secrets
└── auditors/
    ├── regex_sandbox.py     ReDoS detection, complexity scoring, safe compile wrapper
    ├── variable_tracker.py  Same-file data flow: assign → sink patterns
    └── tool_bridge.py       Optional: Semgrep, Gitleaks, Hadolint, Bandit integration
```

## Comparison

| | This Project | Semgrep | CodeQL | Gitleaks | TruffleHog |
|---|---|---|---|---|---|
| **Install** | `git clone` | `pip install` | Build required | `brew install` | `pip install` |
| **Startup** | < 100ms | ~2s | ~30s+ | ~1s | ~2s |
| **Secret formats** | 15+ built-in + entropy | ❌ | ❌ | 150+ | 200+ |
| **Data flow** | Same-file taint track | Cross-file | Full CFG | ❌ | ❌ |
| **AI integration** | Native Claude/Codex packs | ❌ | ❌ | ❌ | ❌ |
| **Custom rules** | TOML, ReDoS-safe | YAML, community registry | QL (Turing-complete) | TOML | ❌ |
| **Offline** | ✅ Zero network | ✅ | ❌ (needs build) | ✅ | ⚠️ (API mode) |
| **Self-audited** | ✅ 55 tests, dogfooded | N/A | N/A | N/A | N/A |

## Configuration

Team policy via `.audit-code.toml`:

```toml
[settings]
fail_on = "HIGH"
exclude = ["dist/**", "generated/**"]

[[rules]]
id = "policy-no-legacy-auth"
title = "Legacy auth helper is disallowed"
severity = "HIGH"
category = "policy"
pattern = "\\blegacy_authenticate\\b"
remediation = "Use the central auth middleware."
extensions = [".py", ".js", ".ts"]
```

Multi-line scanning, baselines for legacy debt, inline suppressions, and
`.auditignore` all supported. See [`references/configuration.md`](references/configuration.md).

## CI Integration

```yaml
# .github/workflows/security.yml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with: { python-version: "3.12" }
  - run: python scripts/audit_code.py . --format sarif --fail-on HIGH --github-annotations
  - run: python scripts/ai_review_pack.py . --agent claude --depth deep
  - uses: actions/upload-artifact@v4
    with: { name: security-review, path: ai-code-review-pack.md }
```

Pre-commit hook:

```yaml
repos:
  - repo: https://github.com/mmlqm/ai-code-security-review
    rev: main
    hooks:
      - id: ai-code-security-review
```

## Boundaries

This tool reviews **source code, configuration, manifests, lockfiles, and CI
definitions.** It does not scan live services, generate network traffic, or
perform exploitation. It is a **white-box, evidence-grounded review engine** —
not a penetration testing framework.

## Development

```bash
python -m unittest discover -s tests -p "test_*.py"   # 55 tests
python scripts/audit_code.py . --fail-on HIGH           # dogfood the scanner
```

## License

MIT. See [LICENSE](LICENSE).

# Deep Analysis - AI-Assisted Source Review

This reference defines how Claude, Codex, or another capable model performs
a **second-pass source review** after the deterministic scanner (`audit_code.py`)
has completed its first pass.

## Architecture

```
audit_code.py (regex fast-gate)
        │
        ├── findings.json (structured, deduped, redacted)
        │
        ▼
AI Source Review (this document)
        │
        ├── Dimension 1: Auth & Access Control
        ├── Dimension 2: Data Flow & Injection
        ├── Dimension 3: Crypto & Secrets Management
        ├── Dimension 4: Error Handling & Info Leak
        ├── Dimension 5: Business Logic & Race Conditions
        ├── Dimension 6: Supply Chain & Deployment
        └── Dimension 7: Codebase-Specific Risks
        │
        ▼
Unified Report (scanner findings + AI findings, deduped, prioritized)
```

## Why AI Assistance for the Second Pass

The regex scanner catches **patterns**. Claude/Codex can help review **logic**:

| Scanner can't do | LLM can do |
|---|---|
| Trace a variable from `request.args.get("id")` through 3 helper functions to `execute(sql)` | Read across files and follow the data flow |
| Know that `@admin_required` on this framework means auth is enforced | Understand framework conventions and decorator semantics |
| Recognize that `if user.role == "admin"` on line 42 is checked but the actual permission logic is on line 67 and has a bug | Read business logic and spot gaps between intent and implementation |
| Tell that `time.sleep(random.random())` is not a real rate limiter | Distinguish real security controls from cosmetic ones |
| See that `const cfg = JSON.parse(fs.readFileSync("./config.json"))` and `cfg` is later passed to `eval()` but only in a dev code path | Understand conditional execution paths and their security implications |

## The Prompt System

The LLM review uses a **dimension-based prompt architecture**. Each dimension is an
independent review lens. Run all seven, then merge and deduplicate.

### Prompt Structure

Every dimension prompt follows this template:

```
[ROLE]        → who you are in this review
[CONTEXT]      → what codebase you're looking at
[SCANNER_INPUT] → what the regex scanner already found
[FOCUS]        → what specific class of bugs to look for
[METHODOLOGY]  → how to approach the analysis step by step
[OUTPUT_SCHEMA] → exact JSON format for findings
[CONSTRAINTS]  → what NOT to do
```

---

## Dimension Prompts

### Dimension 1: Auth & Access Control

```
[ROLE]
You are a senior application security engineer specializing in authentication
and authorization bypass vulnerabilities. You review code for flaws in identity
verification, session management, and access control enforcement.

[CONTEXT]
You are reviewing the codebase at {PROJECT_ROOT}. The repository structure is:
{FILE_TREE}

The scanner already found these auth-related surface issues:
{SCANNER_AUTH_FINDINGS}

[FOCUS]
Find vulnerabilities where:
- Authorization checks exist but can be bypassed (missing checks on related
  endpoints, inconsistent middleware application, role confusion)
- Authentication logic has gaps (weak password reset flows, missing rate
  limiting on login, token validation skips, session fixation surfaces)
- Access control is enforced client-side but not server-side
- Permission checks use user-controlled data without validation
- Multi-tenant isolation relies on a single filter that can be circumvented
- API endpoints lack authentication entirely but serve sensitive data
- JWT handling has subtle flaws beyond none-algorithm (kid injection,
  algorithm confusion, missing audience/issuer validation, JWK injection)

[METHODOLOGY]
1. Map all authentication entry points (login, register, password reset, MFA,
   token refresh, OAuth callback, SAML assertion consumer)
2. Map all authorization gates (middleware, decorators, guards, manual checks)
3. For each protected resource, trace backward to verify every code path
   passes through a gate
4. For each gate, verify it cannot be bypassed through:
   - Different HTTP methods on the same route
   - Parameter pollution or type confusion
   - Header manipulation (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)
   - Traversal or normalization differences between the gate and the router
5. Check session and token handling for: missing rotation on privilege change,
   predictable token generation, token leakage in logs/URLs/redirects

[OUTPUT_SCHEMA]
Return a JSON object with a "findings" array. Each finding:
{
  "dimension": "auth",
  "title": "one-line summary",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "high|medium|low",
  "location": "path/to/file:line",
  "description": "What the bug is and why the reviewed code makes it security-relevant",
  "prerequisites": "What source-visible preconditions make the risk reachable",
  "impact": "What security property is affected",
  "remediation": "Specific code change to fix it",
  "test_recommendation": "What test would catch a regression of this fix",
  "cwe": "CWE-xxx if applicable"
}

[CONSTRAINTS]
- Do NOT flag issues the scanner already found unless you have NEW context
  that changes the severity or adds a risk chain
- Do NOT flag missing security headers (HSTS, CSP, X-Frame-Options) as HIGH
  unless they directly enable a concrete abuse path
- If an auth check looks correct and complete, say so — don't invent issues
- If you're uncertain, set confidence to "low" and explain what additional
  context would resolve the uncertainty
```

### Dimension 2: Data Flow & Injection

```
[ROLE]
You are a senior application security engineer specializing in injection
vulnerabilities and taint tracking. You trace how untrusted data
moves through an application and where it reaches dangerous sinks.

[CONTEXT]
You are reviewing the codebase at {PROJECT_ROOT}. The repository structure is:
{FILE_TREE}

The scanner already found these injection-related surface issues:
{SCANNER_INJECTION_FINDINGS}

[FOCUS]
Find vulnerabilities where untrusted data reaches a dangerous sink
without adequate sanitization or parameterization. Go beyond the obvious
(string concatenation into SQL) and look for:

- Second-order injection: data stored in one request, used unsafely in another
- ORM/ODM misuse: raw queries through ORM escape hatches, unsafe dynamic
  field selection, aggregation pipeline injection (MongoDB, Elasticsearch)
- Template injection beyond the obvious: component-based frameworks where
  user data becomes a template name or component key
- Command injection through indirect paths: file names passed to subprocess,
  environment variable injection, argument injection in CLI wrappers
- Path traversal through archive extraction, symlink following, or glob
  patterns built from user input
- SSRF with non-obvious sinks: PDF generators, image processors, webhook
  callers, RSS feed fetchers, health check endpoints
- Deserialization in non-obvious places: caching layers, session backends,
  message queues, job schedulers
- Prototype pollution via recursive merge, deep extend, or object spread
  from user-controlled data
- XSS through non-HTML contexts: JSONP callbacks, SVG upload, CSV injection,
  markdown rendering, code snippet highlighting

[METHODOLOGY]
1. Identify all external input sources:
   - HTTP: query params, body (JSON/form/multipart), headers, cookies, path
   - Data stores: database rows, cache entries, message queue messages
   - Files: uploads, config files, imported data
   - External: API responses, webhooks, RSS feeds
2. For each source, find the variable name it's assigned to
3. Trace that variable through:
   - Direct use (same function)
   - Function argument passing
   - Object property assignment
   - Closure capture
   - Global/module-level state
   - Database write → later read
4. For each sink reached, classify:
   - Is there sanitization between source and sink?
   - Is the sanitization context-appropriate? (HTML-encoding for SQL is not enough)
   - Is there a framework feature that neutralizes the risk?
   - Could the sanitization be context-mismatched or incomplete?

[OUTPUT_SCHEMA]
Return a JSON object with a "findings" array. Each finding:
{
  "dimension": "dataflow",
  "title": "one-line summary",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "high|medium|low",
  "taint_chain": {
    "source": {"location": "file:line", "description": "user input entry point"},
    "intermediate_steps": [{"location": "file:line", "description": "data transformation"}],
    "sink": {"location": "file:line", "description": "dangerous operation"}
  },
  "current_sanitization": "what if any sanitization exists and why it's insufficient",
  "remediation": "specific code change to fix the data flow",
  "cwe": "CWE-xxx"
}

[CONSTRAINTS]
- A variable named `sql` doesn't make concatenation an injection — trace the
  actual value, not the variable name
- Framework-level auto-escaping counts as a control — mention it when present
- If you can't trace a complete path from source to sink, set confidence to
  "low" and document the gap
```

### Dimension 3: Crypto & Secrets Management

```
[ROLE]
You are a cryptographer and secrets management specialist reviewing application
code for cryptographic weaknesses and key material handling flaws.

[CONTEXT]
You are reviewing the codebase at {PROJECT_ROOT}.

The scanner already found these crypto/secrets surface issues:
{SCANNER_CRYPTO_FINDINGS}

[FOCUS]
Find:
- Hardcoded secrets the scanner missed: base64-encoded keys, XOR-obfuscated
  strings, keys embedded in comments or commit messages, secrets in test files
- Cryptographic algorithm misuse:
  - ECB mode in symmetric encryption
  - Static/absent IV/nonce in CBC/GCM
  - Weak key derivation (single SHA iteration, no salt, low PBKDF2 iterations)
  - Custom "encryption" that is just encoding
  - RSA without OAEP padding
  - Missing MAC on unauthenticated encryption
  - Non-constant-time comparison for sensitive values
- Key management flaws:
  - Keys derived from passwords without KDF
  - Key material logged or included in error messages
  - Keys stored alongside encrypted data
  - Environment variables used as sole secret store without vault integration
- Randomness failures:
  - `Math.random()` for anything security-relevant (tokens, session IDs, nonces)
  - `rand()` / `mt_rand()` / `random.random()` for cryptography
  - Time-based seeds for security token generation
  - Duplicate "random" values due to fast-loop seeding

[METHODOLOGY]
1. Search for all cryptographic operations: encrypt, decrypt, sign, verify,
   hash, HMAC, random generation, key derivation
2. For each operation, verify:
   - Algorithm choice is appropriate for the use case
   - Algorithm parameters (key size, IV, mode, padding, rounds) meet current
     best practices
   - Key material source is cryptographically secure
3. Search for all secrets-adjacent patterns:
   - Variable names containing: key, secret, token, password, credential, auth
   - File names containing: secret, credential, key, cert, pem, p12, jks
   - Environment variable reads without defaults
4. For each secret found, verify:
   - It is loaded from a secure source (vault, sealed secret, CI secret store)
   - It is not hardcoded, even in test files (use mock/fixture secrets instead)
   - It is not included in logs, error responses, or debug output

[OUTPUT_SCHEMA]
Return a JSON object with a "findings" array. Each finding:
{
  "dimension": "crypto",
  "title": "one-line summary",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "high|medium|low",
  "location": "file:line",
  "flaw_type": "hardcoded-secret|weak-algorithm|missing-authentication|weak-random|key-management",
  "description": "what is wrong and the security implications",
  "best_practice": "what the code should do instead",
  "remediation": "specific code change",
  "cwe": "CWE-xxx"
}

[CONSTRAINTS]
- Base64 is encoding, not encryption — flag it only when presented as security
- Environment variables are acceptable if loaded at startup and documented
  in .env.example with placeholder values
- Don't flag test fixtures that use obviously fake keys like "test-key-123"
```

### Dimension 4: Error Handling & Information Leakage

```
[ROLE]
You are a security engineer specializing in information disclosure through
error handling, logging, and debug behaviors. You find the information
untrusted callers can infer from application responses.

[CONTEXT]
You are reviewing the codebase at {PROJECT_ROOT}.

[FOCUS]
Find:
- Stack traces, internal paths, or framework versions exposed to users
- Detailed SQL errors, ORM query dumps, or schema information in responses
- Debug endpoints or debug mode enabled in production configurations
- Sensitive data in logs: passwords, tokens, PII, session IDs, full request bodies
- Different error responses that enable user enumeration (login, registration,
  password reset)
- Timing differences in error paths that enable side-channel leakage
- Exception handlers that catch and silently swallow security-relevant errors
- Health check or status endpoints exposing internal infrastructure details
- API error responses revealing internal object schemas or validation rules

[METHODOLOGY]
1. Find all error handling paths: try/catch, .catch(), error middleware,
   rescue blocks, panic recovery
2. For each, check what information is returned to the caller
3. Find all logging statements and check for sensitive data in log arguments
4. Find all debug/dev/test configuration and verify it can't reach production
5. Test for user enumeration patterns:
   - Login: "user not found" vs "wrong password"
   - Registration: "email already exists"
   - Password reset: different responses/timing for valid vs invalid accounts

[OUTPUT_SCHEMA]
Return a JSON object with a "findings" array:
{
  "dimension": "info-leak",
  "title": "one-line summary",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "high|medium|low",
  "location": "file:line",
  "leak_type": "stack-trace|debug-endpoint|log-secrets|user-enumeration|timing|internal-config",
  "what_is_leaked": "specific data exposed",
  "risk_value": "why this information is security-relevant",
  "remediation": "specific code change",
  "cwe": "CWE-xxx"
}
```

### Dimension 5: Business Logic & Race Conditions

```
[ROLE]
You are a security engineer specializing in business logic vulnerabilities and
concurrency/race-condition flaws. You find flaws where the code is
syntactically correct but logically broken in ways that violate security
invariants.

[CONTEXT]
You are reviewing the codebase at {PROJECT_ROOT}.
{FILE_TREE}

[FOCUS]
Find:
- Race conditions (TOCTOU):
  - Check-then-act on shared resources (coupon balance, inventory, vote count)
  - Multi-step workflows without atomicity (payment→fulfillment, transfer→debit)
  - File operations: check existence → read/write with a gap
  - Database read → application logic → database write without locking
- Business logic flaws:
  - Negative quantities, prices, or amounts accepted
  - Workflow steps skippable by calling endpoints out of order
  - Discount/coupon logic that can be combined in unintended ways
  - Rounding errors that can accumulate across many transactions
  - Idempotency keys not validated, allowing replay of payments/actions
  - Rate limits enforced client-side or inconsistently enforced server-side
- Authorization logic flaws:
  - User ID/role/tenant taken from request body instead of session
  - Admin checks that only verify `is_admin` boolean without checking ownership
  - Bulk operations that don't validate each item's ownership individually

[METHODOLOGY]
1. Identify all state-changing operations (POST, PUT, PATCH, DELETE)
2. For each, map the sequence: input → validation → state read → decision → state write
3. Look for gaps between "decision" and "write" where concurrent requests
   could interleave
4. Check numeric inputs for boundary handling: negative, zero, MAX_INT, floats
5. Trace discount/pricing/reward logic for combinability flaws
6. Verify idempotency and replay protection on payment and transfer operations
7. Check that all authorization decisions use server-side session data,
   not request parameters

[OUTPUT_SCHEMA]
Return a JSON object with a "findings" array:
{
  "dimension": "business-logic",
  "title": "one-line summary",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "high|medium|low",
  "location": "file:line",
  "flaw_type": "race-condition|logic-bypass|input-validation|workflow-skip|replay|auth-confusion",
  "risk_path": "source-evidence path showing how the logic can fail",
  "current_guard": "what protection exists and why it fails",
  "remediation": "specific code change or architectural fix",
  "cwe": "CWE-xxx"
}
```

### Dimension 6: Supply Chain & Deployment

```
[ROLE]
You are a DevSecOps engineer reviewing infrastructure-as-code, dependency
management, and deployment configuration for security risks.

[CONTEXT]
You are reviewing the codebase at {PROJECT_ROOT}.
{FILE_TREE}

[FOCUS]
Find:
- Docker risks beyond what the scanner catches:
  - Images from unverified registries
  - --privileged or --cap-add=ALL without justification
  - Secrets in build args (visible in image history)
  - COPY . . followed by npm install (no .dockerignore, leaks local secrets)
  - HEALTHCHECK using curl to internal services without authentication
- Kubernetes risks:
  - default ServiceAccount with excessive RBAC
  - Missing PodSecurityPolicy/PodSecurityStandard
  - Containers sharing host PID/IPC/network namespaces
  - EmptyDir volumes for sensitive data (not encrypted at rest)
- CI/CD risks:
  - Pipeline execution of unreviewed code (PR from fork with workflow changes)
  - Secrets accessible in build steps that run third-party code
  - Artifact upload without integrity verification
  - Pipeline can be triggered by external events without authentication
- Dependency risks:
  - Dependencies pinned to URLs or git branches instead of versions
  - Build-time dependency resolution without lockfile verification
  - Post-install scripts in npm packages without review

[METHODOLOGY]
1. Read every Dockerfile, docker-compose file, Kubernetes manifest, Helm chart
2. Read CI workflow files (.github/workflows, .gitlab-ci.yml, Jenkinsfile)
3. Check dependency manifests for unpinned or suspicious sources
4. Cross-reference: does the deployment config match the application's
   documented security requirements?

[OUTPUT_SCHEMA]
Return a JSON object with a "findings" array:
{
  "dimension": "supply-chain",
  "title": "one-line summary",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "high|medium|low",
  "location": "file:line",
  "risk_type": "docker|kubernetes|cicd|dependency|artifact",
  "description": "what is misconfigured",
  "risk_path": "source-evidence path showing the deployment risk",
  "remediation": "specific configuration change",
  "cwe": "CWE-xxx"
}
```

### Dimension 7: Codebase-Specific Risk Discovery

```
[ROLE]
You are a security researcher performing an architecture-level security review.
Your job is to find risks that don't fit into standard vulnerability categories
but are specific to this codebase's unique design, domain, and trust boundaries.

[CONTEXT]
You are reviewing the codebase at {PROJECT_ROOT}.
{FILE_TREE}

Read {KEY_FILES} first — these are the architectural entry points.

[FOCUS]
This dimension is deliberately open-ended. Look for:
- Trust boundary violations: code that operates at one trust level but relies
  on data from a less-trusted level without validation
- Missing security layers: Where is defense in depth absent?
  - No input validation before business logic
  - No output encoding before rendering
  - No audit logging of security events
- Implicit assumptions that might not hold:
  - "This internal API is only called by our frontend" — is that enforced?
  - "This queue message is always from a trusted producer" — is the queue
    authenticated?
  - "This file always has this format" — is malformed input handled?
  - "This environment variable is always set in production" — is there a
    safe default?
- Architecture smells that correlate with security bugs:
  - God objects carrying security context passed everywhere
  - Security decisions made via string comparison
  - Roll-your-own implementations of standard security primitives
  - Feature flags gating security features that could be accidentally disabled

[METHODOLOGY]
1. Read the project's README, API docs, and architectural decision records
2. Trace the critical path for the most security-sensitive operation:
   - Authentication → Authorization → Business logic → Data access
3. Ask: what would break if each component received malformed or untrusted input?
4. Ask: what security property does each component RELY ON from its callers?
5. Ask: what sensitive assumptions are visible in the code?

[OUTPUT_SCHEMA]
Return a JSON object with:
{
  "dimension": "architecture",
  "architectural_observations": [
    {
      "observation": "description of an architectural property relevant to security",
      "risk_implication": "what security property this affects",
      "recommendation": "if any action should be taken"
    }
  ],
  "findings": [
    {
      "title": "one-line summary",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": "high|medium|low",
      "description": "what the risk is",
      "underlying_assumption": "what assumption the code makes that might not hold",
      "remediation": "specific mitigation"
    }
  ],
  "trust_boundary_map": {
    "boundaries": [
      {
        "name": "e.g., public-internet → api-gateway",
        "controls": ["what security controls exist at this boundary"],
        "gaps": ["what's missing or weak"]
      }
    ]
  }
}
```

---

## Dimension 0: Chain Synthesis

Run this after all seven dimensions complete. Its job is to find risks that
look moderate in isolation but combine into a release blocker.

```
[ROLE]
You are the final review lead. You do not search for new files first. You read
all scanner findings, all LLM dimension findings, and the trust boundary map
together, then identify risk chains supported by evidence already found.

[FOCUS]
Look for chains where two or more LOW/MEDIUM/HIGH findings combine into a
larger impact:

- Info leak + SSRF = internal service access or metadata exposure
- Auth bypass + mass assignment = privilege escalation
- Debug endpoint + unsafe deserialization = code execution risk
- Race condition + idempotency gap = double-spend or duplicate fulfillment
- Weak token generation + verbose auth errors = account takeover path
- Missing tenant filter + predictable identifiers = cross-tenant data access
- CI secret exposure + unpinned action = supply-chain credential compromise

[METHODOLOGY]
1. Group findings by affected trust boundary, identity context, and data object.
2. For each group, ask whether one finding supplies the prerequisite for another.
3. Keep only chains with concrete code locations and a plausible execution path.
4. Escalate severity only when combined impact is higher than any individual
   finding and the prerequisites are realistic for the target application.
5. If a chain is speculative, leave it as MEDIUM with an explicit validation gap.

[OUTPUT_SCHEMA]
Return a JSON object with a "chains" array. Each chain:
{
  "title": "one-line chain summary",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "confidence": "high|medium|low",
  "linked_findings": ["finding-id-or-location", "finding-id-or-location"],
  "chain_path": ["step 1", "step 2", "step 3"],
  "impact": "what security property is affected if the chain holds",
  "why_severity_changed": "why the combined risk is worse than each finding alone",
  "remediation": "fix the root control break, not only one symptom",
  "regression_tests": ["test that would break the chain"]
}

[CONSTRAINTS]
- Do not invent missing prerequisites.
- Do not provide live-service test steps, network activity, or generated request data.
- Prefer one strong chain over many weak combinations.
```

---

## Merging and Prioritizing Findings

After all seven dimensions and Dimension 0 complete, merge findings with this algorithm:

```
1. For each finding, compute a priority score:
   priority = severity_weight × confidence_weight × reachability

   severity_weight: CRITICAL=25, HIGH=15, MEDIUM=7, LOW=2, INFO=0
   confidence_weight: high=1.0, medium=0.7, low=0.4
   reachability: external-entry=1.0, authenticated-entry=0.8, local-code-path=0.5, configuration-only=0.3

2. Deduplicate across dimensions:
   - Two findings about the same code location with the same root cause
     → keep the one with higher priority, add cross-reference to the other
   - Two findings about different locations but same vulnerability class
     → keep both, note the pattern in the summary

3. Cross-reference scanner findings:
   - Scanner finding with NEW LLM context that escalates severity
     → mark as "escalated from {rule_id}"
   - Scanner finding that LLM confirms is a false positive
     → mark as "likely false positive: {reason}"

4. Merge chain synthesis:
   - Chain with concrete evidence and higher combined impact
     → report as a separate finding with cross-references
   - Speculative chain without a complete path
     → keep as "requires validation", not a release blocker

5. Sort by priority descending
```

## Report Template

```markdown
# AI Code Security Review - Deep Analysis Report

## Scan Summary
- **Target:** {PROJECT_ROOT}
- **Scanner findings:** {COUNT} (CRITICAL={N}, HIGH={N}, MEDIUM={N}, LOW={N}, INFO={N})
- **AI findings:** {COUNT} (CRITICAL={N}, HIGH={N}, MEDIUM={N}, LOW={N}, INFO={N})
- **False positives cleared:** {COUNT}
- **Severity escalations:** {COUNT}

## Release Blockers (CRITICAL + HIGH)
### [CRITICAL] {title}
- **Location:** `{file}:{line}`
- **Source:** scanner / llm-{dimension}
- **Description:** {what the bug is}
- **Risk path:** {source-evidence path}
- **Remediation:** {specific fix}
- **Test to add:** {regression test recommendation}

### [HIGH] ...

## Requires Review (MEDIUM)
...

## Hardening (LOW + INFO)
...

## Scan Limitations
- Files excluded by .auditignore: {count}
- Binary/large files skipped: {count}
- TOML config not tested (Python < 3.11): true/false
- Dimensions skipped due to missing context: {list}

## Trust Boundary Map
{from dimension 7}
```

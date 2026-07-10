"""Built-in rule catalog for audit_code.py.

Rules live outside the scanner engine so coverage can grow without making the
CLI, reporting, and traversal code harder to reason about.
"""

from __future__ import annotations

import re


def builtin_rules(AuditRule, _rx):
    """Rule catalog tuned for generated application code and delivery gates."""
    return [
        AuditRule(
            "secret-aws-access-key", "Hardcoded AWS access key", "CRITICAL", "secrets",
            _rx(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b", 0),
            "Move cloud credentials to a secret manager and rotate the exposed key.",
            cwe="CWE-798", confidence="high", scan_comments=True,
        ),
        AuditRule(
            "secret-private-key", "Private key material committed", "CRITICAL", "secrets",
            _rx(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----", 0),
            "Remove private keys from source, rotate them, and load them from protected secret storage.",
            cwe="CWE-798", confidence="high", scan_comments=True,
        ),
        AuditRule(
            "secret-generic-hardcoded", "Hardcoded secret-like value", "HIGH", "secrets",
            _rx(r"\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|"
                r"private[_-]?key|access[_-]?key)\b\s*[:=]\s*[\"'](?P<value>[^\"']{8,})[\"']"),
            "Do not commit runtime secrets. Load them from environment variables or a secret manager.",
            cwe="CWE-798", confidence="medium", scan_comments=True, validator="secret_value",
        ),
        AuditRule(
            "secret-unquoted-config-value", "Unquoted secret-like config value", "HIGH", "secrets",
            _rx(r"^\s*(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|"
                r"private[_-]?key|access[_-]?key)\s*[:=]\s*(?P<value>[^\s#\"'][^#\r\n]{7,})\s*(?:#.*)?$"),
            "Do not commit runtime secrets in config files. Load them from environment variables or a secret manager.",
            cwe="CWE-798", confidence="medium", scan_comments=True,
            extensions=(".yml", ".yaml", ".toml", ".properties", ".ini", ".conf", ".cfg", ".env"),
            validator="secret_value",
        ),
        AuditRule(
            "secret-high-entropy-string", "High-entropy string may be an unknown token", "MEDIUM", "secrets",
            _rx(r"(?P<value>[A-Za-z0-9+/=_-]{32,})", 0),
            "Verify this is not a hardcoded credential; if it is, move it to a secret manager and rotate it.",
            cwe="CWE-798", confidence="low", scan_comments=True, validator="secret_entropy_value",
        ),
        AuditRule(
            "secret-default-credential", "Default or placeholder credential", "HIGH", "secrets",
            _rx(r"\b(?:password|passwd|pwd|jwt[_-]?secret|secret[_-]?key|client[_-]?secret)\b\s*[:=]\s*"
                r"[\"'](?:admin|password|passwd|changeme|change_me|secret|test|demo|123456|dev|local)[\"']"),
            "Replace generated placeholder credentials with required configuration and startup validation.",
            cwe="CWE-798", confidence="high", scan_comments=True,
        ),
        AuditRule(
            "auth-placeholder", "Authorization placeholder or bypass", "HIGH", "auth",
            _rx(r"(?:TODO|FIXME|HACK).{0,80}\b(?:auth|authorization|permission|rbac|access control)\b|"
                r"\breturn\s+true\s*(?:#|//).{0,80}\b(?:auth|permission|temporary|todo|bypass)\b|"
                r"\b(?:skipAuth|disableAuth|authRequired)\b\s*[:=]\s*(?:true|false)"),
            "Replace placeholder authorization with explicit policy checks and negative tests.",
            cwe="CWE-863", confidence="medium", scan_comments=True, sensitive_boost=True,
            validator="not_rule_definition",
        ),
        AuditRule(
            "ai-placeholder-in-sensitive-code", "Generated-code placeholder in sensitive path", "MEDIUM", "delivery",
            _rx(r"\b(?:TODO|FIXME|HACK|not implemented|mock implementation|temporary bypass|"
                r"for demo only|replace in production|dummy (?:secret|password|token|implementation|data|user)|"
                r"placeholder (?:secret|password|token|implementation|auth|user))\b"),
            "Resolve generated placeholders before delivery, especially in auth, payment, admin, or session code.",
            confidence="medium", scan_comments=True, sensitive_boost=True,
            validator="placeholder_context",
        ),
        AuditRule(
            "sql-python-dynamic-execute", "Dynamic SQL passed to execute()", "HIGH", "injection",
            _rx(r"\.execute\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+)|[^)]*\.format\s*\()"),
            "Use parameterized queries or ORM bind parameters instead of formatted SQL strings.",
            cwe="CWE-89", confidence="medium", extensions=(".py",),
        ),
        AuditRule(
            "sql-python-variable-track", "Dynamic SQL variable later passed to execute()", "HIGH", "injection",
            _rx(r"\b[A-Za-z_][A-Za-z0-9_]*\b"),
            "Use parameterized queries or ORM bind parameters instead of carrying formatted SQL into execute().",
            cwe="CWE-89", confidence="medium", extensions=(".py",), scan_mode="tracked_variable",
        ),
        AuditRule(
            "sql-js-template-query", "SQL query built with template interpolation", "HIGH", "injection",
            _rx(r"\b(?:query|execute|raw)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{"),
            "Use prepared statements or parameter binding; never interpolate request data into SQL.",
            cwe="CWE-89", confidence="medium", extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        ),
        AuditRule(
            "shell-python-shell-true", "subprocess called with shell=True", "HIGH", "injection",
            _rx(r"\bsubprocess\.[a-zA-Z_]+\s*\([^)]*shell\s*=\s*True"),
            "Call subprocess with an argument list and validate each argument.",
            cwe="CWE-78", confidence="high", extensions=(".py",),
        ),
        AuditRule(
            "shell-python-os-system", "Shell command execution sink", "HIGH", "injection",
            _rx(r"\b(?:os\.system|os\.popen|commands\.getoutput)\s*\("),
            "Avoid shell execution for request-controlled data; use safe library APIs.",
            cwe="CWE-78", confidence="medium", extensions=(".py",),
        ),
        AuditRule(
            "shell-python-variable-track", "Shell command variable later executed", "HIGH", "injection",
            _rx(r"\b[A-Za-z_][A-Za-z0-9_]*\b"),
            "Avoid building shell command strings before execution; use argument arrays and strict allowlists.",
            cwe="CWE-78", confidence="medium", extensions=(".py",), scan_mode="tracked_variable",
        ),
        AuditRule(
            "shell-js-child-process", "child_process exec sink", "HIGH", "injection",
            _rx(r"\b(?:child_process\.)?(?:exec|execSync)\s*\("),
            "Prefer execFile/spawn with an argument array and strict allowlists.",
            cwe="CWE-78", confidence="medium", extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        ),
        AuditRule(
            "eval-dynamic-code", "Dynamic code evaluation", "HIGH", "injection",
            _rx(r"\b(?:eval|exec)\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn(?:New)?Context\s*\("),
            "Remove dynamic code evaluation or constrain it with a purpose-built parser/sandbox.",
            cwe="CWE-94", confidence="medium",
            extensions=(".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        ),
        AuditRule(
            "deser-python-unsafe", "Unsafe Python deserialization", "HIGH", "deserialization",
            _rx(r"\b(?:pickle|marshal|dill)\.loads?\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)"),
            "Do not deserialize untrusted data; use JSON or safe loaders with schema validation.",
            cwe="CWE-502", confidence="high", extensions=(".py",),
        ),
        AuditRule(
            "deser-generic-unsafe", "Unsafe deserialization sink", "HIGH", "deserialization",
            _rx(r"\b(?:unserialize|ObjectInputStream|BinaryFormatter|JsonConvert\.DeserializeObject)\b"),
            "Add type allowlists and never deserialize user-controlled data into executable object graphs.",
            cwe="CWE-502", confidence="medium",
            extensions=(".php", ".java", ".cs", ".js", ".ts"),
        ),
        AuditRule(
            "ssrf-request-url", "Outbound request uses request-controlled URL", "HIGH", "ssrf",
            _rx(r"\brequests\.(?:get|post|put|delete|request)\s*\([^)]*(?:request\.|args\.get|form\.get)|"
                r"\b(?:fetch|axios\.(?:get|post|request))\s*\(\s*(?:req\.|request\.|ctx\.request)|"
                r"\bhttp\.Get\s*\([^)]*r\.URL\.Query\(\)\.Get"),
            "Validate outbound destinations with scheme and host allowlists; block private network ranges.",
            cwe="CWE-918", confidence="medium",
        ),
        AuditRule(
            "path-traversal-file-read", "File path built from request input", "HIGH", "path-traversal",
            _rx(r"\b(?:send_file|open)\s*\([^)]*(?:request\.|args\.get|form\.get)|"
                r"\bfs\.(?:readFile|createReadStream|writeFile)\s*\([^)]*(?:req\.|request\.|ctx\.request)|"
                r"\bpath\.join\s*\([^)]*(?:req\.|request\.|ctx\.request)"),
            "Normalize and allowlist file paths; keep user input out of filesystem joins.",
            cwe="CWE-22", confidence="medium",
        ),
        AuditRule(
            "tls-verification-disabled", "TLS certificate verification disabled", "HIGH", "crypto",
            _rx(r"\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"),
            "Keep TLS verification enabled and fix the trust store instead of disabling validation.",
            cwe="CWE-295", confidence="high",
        ),
        AuditRule(
            "jwt-verification-disabled", "JWT signature verification disabled", "CRITICAL", "auth",
            _rx(r"jwt\.decode\s*\([^)]*(?:verify\s*=\s*False|verify_signature[\"']?\s*:\s*False|verify_signature[\"']?\s*:\s*false)"),
            "Always verify JWT signatures, issuer, audience, expiry, and allowed algorithms.",
            cwe="CWE-347", confidence="high",
        ),
        AuditRule(
            "weak-hash-for-security", "Weak hash used in security-sensitive code", "MEDIUM", "crypto",
            _rx(r"\b(?:md5|sha1)\s*\("),
            "Use SHA-256+ for integrity and a password hashing function such as Argon2id/bcrypt/scrypt for passwords.",
            cwe="CWE-327", confidence="low", sensitive_boost=True,
        ),
        AuditRule(
            "weak-random-token", "Non-cryptographic randomness for token material", "HIGH", "crypto",
            _rx(r"(?:Math\.random\(\).*?(?:token|secret|password|otp|nonce)|"
                r"(?:token|secret|password|otp|nonce).*?Math\.random\(\)|"
                r"random\.(?:random|randint|choice)\s*\([^)]*\).*?(?:token|secret|password|otp|nonce))"),
            "Use crypto.randomUUID/crypto.getRandomValues, secrets, or a CSPRNG for token generation.",
            cwe="CWE-338", confidence="medium",
        ),
        AuditRule(
            "debug-mode-enabled", "Debug mode enabled", "MEDIUM", "config",
            _rx(r"\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b|app\.run\s*\([^)]*debug\s*=\s*True"),
            "Disable debug mode in production and gate it behind explicit non-production configuration.",
            cwe="CWE-489", confidence="high", extensions=(".py",),
        ),
        AuditRule(
            "cors-wide-open", "Permissive CORS configuration", "MEDIUM", "config",
            _rx(r"Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']|"
                r"\borigin\s*:\s*[\"']\*[\"']|\bapp\.use\s*\(\s*cors\s*\(\s*\)\s*\)"),
            "Restrict CORS origins to trusted frontends and avoid credentials with wildcard origins.",
            cwe="CWE-942", confidence="medium",
        ),
        AuditRule(
            "csrf-disabled", "CSRF protection disabled", "MEDIUM", "auth",
            _rx(r"\bcsrf(?:Protection)?\s*\(\s*\)\.disable\s*\(|\bcsrf_exempt\b|"
                r"\bWTF_CSRF_ENABLED\s*=\s*False\b|\bCSRF_TRUSTED_ORIGINS\s*=.*\*"),
            "Enable CSRF protection on browser-authenticated state-changing routes.",
            cwe="CWE-352", confidence="medium",
        ),
        AuditRule(
            "cookie-insecure", "Cookie security flag disabled", "MEDIUM", "auth",
            _rx(r"\b(?:secure|httpOnly|sameSite)\s*:\s*false\b|"
                r"\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False\b"),
            "Set Secure, HttpOnly, and an appropriate SameSite mode for session cookies.",
            cwe="CWE-614", confidence="medium",
        ),
        AuditRule(
            "error-stack-leak", "Stack trace returned or logged directly", "LOW", "observability",
            _rx(r"\b(?:traceback\.print_exc|err\.stack|error\.stack|exception\.stack)\b"),
            "Return generic errors to users and send detailed traces only to protected logs.",
            cwe="CWE-209", confidence="low",
        ),
        AuditRule(
            "secret-logged", "Secret-like value logged", "HIGH", "secrets",
            _rx(r"\b(?:console\.log|print|logger\.(?:info|debug|error|warn))\s*\([^)]*"
                r"\b(?:password|passwd|secret|token|apiKey|api_key|authorization)\b"),
            "Remove secrets from logs and add redaction at logging boundaries.",
            cwe="CWE-532", confidence="medium", validator="not_rule_definition",
        ),
        AuditRule(
            "docker-root-user", "Container runs as root", "MEDIUM", "deployment",
            _rx(r"^\s*USER\s+root\s*$", re.IGNORECASE | re.MULTILINE),
            "Run containers as a non-root user and set filesystem permissions explicitly.",
            cwe="CWE-250", confidence="high", filenames=("dockerfile*",),
        ),
        AuditRule(
            "docker-latest-image", "Container base image is unpinned or latest", "LOW", "supply-chain",
            _rx(r"^\s*FROM\s+(?P<image>\S+)", re.IGNORECASE),
            "Pin base images by immutable digest or a reviewed version tag.",
            confidence="medium", filenames=("dockerfile*",), validator="docker_from_unpinned",
        ),
        AuditRule(
            "docker-curl-pipe-shell", "Install script piped directly to shell", "HIGH", "supply-chain",
            _rx(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|powershell|pwsh)\b"),
            "Download installers separately, verify checksums/signatures, then execute.",
            cwe="CWE-494", confidence="high",
        ),
        AuditRule(
            "world-writable-permissions", "World-writable permissions", "MEDIUM", "deployment",
            _rx(r"\bchmod\s+(?:-R\s+)?777\b"),
            "Use least-privilege file permissions instead of world-writable directories.",
            cwe="CWE-732", confidence="high",
        ),
        AuditRule(
            "k8s-privileged", "Privileged Kubernetes workload", "HIGH", "deployment",
            _rx(r"^\s*(?:privileged|allowPrivilegeEscalation|hostNetwork|hostPID)\s*:\s*true\s*$",
                re.IGNORECASE | re.MULTILINE),
            "Disable privileged pod options unless there is a reviewed operational exception.",
            cwe="CWE-250", confidence="high", extensions=(".yml", ".yaml"),
        ),
        AuditRule(
            "k8s-root-user", "Kubernetes workload runs as root", "MEDIUM", "deployment",
            _rx(r"^\s*runAsUser\s*:\s*0\s*$", re.IGNORECASE | re.MULTILINE),
            "Set runAsNonRoot and a non-zero runAsUser in pod securityContext.",
            cwe="CWE-250", confidence="high", extensions=(".yml", ".yaml"),
        ),
        AuditRule(
            "jwt-none-algorithm", "JWT none algorithm accepted or configured", "CRITICAL", "auth",
            _rx(r"\b(?:alg|algorithm|algorithms)\b\s*[:=]\s*(?:\[\s*)?[\"']none[\"']"),
            "Never accept the JWT none algorithm; pin a reviewed allowlist such as RS256 or ES256.",
            cwe="CWE-347", confidence="high",
        ),
        AuditRule(
            "express-default-session-secret", "Default Express session secret", "HIGH", "secrets",
            _rx(r"\bsession\s*\(\s*\{[^}\n]*\bsecret\s*:\s*[\"'](?:keyboard cat|secret|changeme|dev|test)[\"']"),
            "Load a high-entropy session secret from protected configuration and rotate defaults.",
            cwe="CWE-798", confidence="high", extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        ),
        AuditRule(
            "django-allowed-hosts-wildcard", "Django ALLOWED_HOSTS wildcard", "MEDIUM", "config",
            _rx(r"\bALLOWED_HOSTS\s*=\s*\[[^\]]*[\"']\*[\"'][^\]]*\]"),
            "Restrict ALLOWED_HOSTS to the exact production hostnames.",
            cwe="CWE-346", confidence="high", extensions=(".py",),
        ),
        AuditRule(
            "mongo-query-from-request", "MongoDB query built directly from request input", "HIGH", "injection",
            _rx(r"\b(?:find|findOne|find_one|updateOne|deleteOne|aggregate)\s*\(\s*(?:req\.(?:body|query|params)|request\.(?:json|args|form))"),
            "Map request input to an allowlisted query shape and reject MongoDB operators from user data.",
            cwe="CWE-943", confidence="medium",
        ),
        AuditRule(
            "mongo-dollar-operator-input", "MongoDB operator accepted from user input", "HIGH", "injection",
            _rx(r"\$\s*(?:where|ne|gt|gte|lt|lte|regex|expr)\b.*(?:req\.|request\.|params|query|body)"),
            "Reject or encode user-controlled MongoDB operators such as $where, $ne, and $regex.",
            cwe="CWE-943", confidence="medium",
        ),
        AuditRule(
            "mass-assignment-js", "Mass assignment from request body", "HIGH", "auth",
            _rx(r"\b(?:Object\.assign|\.create|\.update|\.findOneAndUpdate)\s*\([^)]*(?:req\.body|request\.body|ctx\.request\.body)"),
            "Allowlist assignable fields instead of passing request bodies directly into models.",
            cwe="CWE-915", confidence="medium", extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        ),
        AuditRule(
            "mass-assignment-python", "Mass assignment from request data", "HIGH", "auth",
            _rx(r"\b(?:create|update|get_or_create)\s*\(\s*\*\*(?:request\.(?:json|data|POST)|serializer\.validated_data)|"
                r"\bsetattr\s*\([^,]+,\s*(?:key|field|name)\s*,\s*(?:value|request\.)"),
            "Allowlist model fields before applying request data to persistent objects.",
            cwe="CWE-915", confidence="medium", extensions=(".py",),
        ),
        AuditRule(
            "ssti-render-template-string", "Template rendered from request-controlled string", "HIGH", "injection",
            _rx(r"\brender_template_string\s*\([^)]*(?:request\.|args\.get|form\.get)|"
                r"\bTemplate\s*\([^)]*(?:request\.|args\.get|form\.get)"),
            "Render fixed templates and pass user input only as escaped template variables.",
            cwe="CWE-1336", confidence="high", extensions=(".py",),
        ),
        AuditRule(
            "open-redirect-request", "Redirect target from request input", "MEDIUM", "auth",
            _rx(r"\b(?:redirect|res\.redirect|reply\.redirect)\s*\(\s*(?:request\.|req\.|args\.get|form\.get|query\.)"),
            "Redirect only to relative paths or allowlisted hosts.",
            cwe="CWE-601", confidence="medium",
        ),
        AuditRule(
            "xss-dangerously-set-inner-html", "React dangerouslySetInnerHTML used", "MEDIUM", "xss",
            _rx(r"\bdangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*__html"),
            "Avoid dangerouslySetInnerHTML or sanitize trusted HTML with a reviewed sanitizer.",
            cwe="CWE-79", confidence="medium", extensions=(".jsx", ".tsx", ".js", ".ts"),
        ),
        AuditRule(
            "xss-innerhtml-location", "DOM innerHTML assigned from URL-controlled data", "HIGH", "xss",
            _rx(r"\.innerHTML\s*=\s*(?:location\.|document\.URL|window\.location|new\s+URLSearchParams)"),
            "Write untrusted data with textContent or sanitize before assigning HTML.",
            cwe="CWE-79", confidence="high", extensions=(".js", ".jsx", ".ts", ".tsx", ".html"),
        ),
        AuditRule(
            "cors-wildcard-with-credentials", "Wildcard CORS with credentials", "HIGH", "config",
            _rx(r"(?:Access-Control-Allow-Credentials[\"']?\s*[:=]\s*[\"']?true|credentials\s*:\s*true).*"
                r"(?:Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']|origin\s*:\s*[\"']\*[\"'])|"
                r"(?:origin\s*:\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']).*"
                r"(?:credentials\s*:\s*true|Access-Control-Allow-Credentials[\"']?\s*[:=]\s*[\"']?true)"),
            "Never combine credentialed CORS with wildcard origins; use explicit trusted origins.",
            cwe="CWE-942", confidence="high",
        ),
        AuditRule(
            "bcrypt-low-rounds", "Weak bcrypt work factor", "MEDIUM", "crypto",
            _rx(r"\bbcrypt\.(?:hash|hashSync|gensalt|gensaltSync)\s*\([^)]*(?:rounds\s*=\s*)?[1-7]\b"),
            "Use a reviewed bcrypt cost factor appropriate for the service latency budget.",
            cwe="CWE-916", confidence="medium",
        ),
        AuditRule(
            "terraform-public-s3", "Public S3 ACL in infrastructure code", "HIGH", "deployment",
            _rx(r"\bacl\s*=\s*[\"']public-(?:read|read-write)[\"']"),
            "Keep object storage private by default and expose content through reviewed access controls.",
            cwe="CWE-732", confidence="high", extensions=(".tf", ".hcl"),
        ),
        AuditRule(
            "python-unpinned-dependency", "Python dependency is not pinned", "LOW", "supply-chain",
            _rx(r"^\s*[A-Za-z0-9_.-]+(?:\[[^\]]+\])?\s*(?:[<>=~!]=?\s*[^#\s]+)?\s*(?:#.*)?$"),
            "Pin dependencies in application builds or compile them into a reviewed lock file.",
            confidence="medium", filenames=("requirements*.txt",), validator="requirements_unpinned",
        ),
        AuditRule(
            "node-broad-dependency", "Node dependency uses broad version range", "LOW", "supply-chain",
            _rx(r"[\"'][^\"']+[\"']\s*:\s*[\"'](?:\*|latest|[\^~][^\"']+)[\"']"),
            "Use lockfiles and reviewed, reproducible dependency versions for deployable artifacts.",
            confidence="medium", filenames=("package.json",),
        ),
    ]


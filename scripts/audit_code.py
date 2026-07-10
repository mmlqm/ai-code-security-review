#!/usr/bin/env python3
"""
audit_code.py - offline security readiness checks for AI-generated code.

The scanner is intentionally deterministic and stdlib-only so it can run in CI
before AI-authored code is accepted for delivery. It looks for patterns that are
common in generated code: hardcoded secrets, auth placeholders, insecure defaults,
injection sinks, weak crypto, unsafe deserialization, permissive deployment
settings, and dependency hygiene gaps.

This script is packaged for a Codex skill. It performs local static review only:
no live target reconnaissance, network scanning, exploitation, or bypass tooling.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Pattern


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 2, "INFO": 0}

DEFAULT_IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode",
    ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    "node_modules", "vendor", "dist", "build", "target", "out",
    "coverage", ".next", ".nuxt", ".cache", ".terraform",
}

TEST_PATH_PARTS = {
    "test", "tests", "__tests__", "__mocks__", "spec", "specs",
    "fixtures", "fixture", "examples", "example",
}

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".php", ".rb", ".cs", ".cpp", ".cc", ".c",
    ".h", ".hpp", ".rs", ".kt", ".kts", ".swift", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".cfg",
    ".xml", ".gradle", ".properties", ".env",
}

SPECIAL_FILENAMES = {
    "dockerfile", "dockerfile.dev", "dockerfile.prod",
    "docker-compose.yml", "docker-compose.yaml",
    "package.json", "requirements.txt", "requirements-dev.txt",
    "pyproject.toml", "poetry.lock", "uv.lock", "pdm.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "cargo.toml",
    ".env", ".env.local", ".env.development", ".env.production",
}

SENSITIVE_PATH_RE = re.compile(
    r"(auth|login|jwt|token|secret|session|permission|rbac|acl|admin|payment|billing|checkout)",
    re.IGNORECASE,
)

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|"
    r"private[_-]?key|access[_-]?key)\b\s*[:=]\s*[\"'])([^\"']+)([\"'])"
)


Validator = Callable[[re.Match[str], str, Path], bool]


@dataclass(frozen=True)
class AuditRule:
    id: str
    title: str
    severity: str
    category: str
    pattern: Pattern[str]
    remediation: str
    cwe: str = ""
    confidence: str = "medium"
    extensions: tuple[str, ...] = ()
    filenames: tuple[str, ...] = ()
    scan_comments: bool = False
    sensitive_boost: bool = False
    validator: str = ""

    def matches_file(self, path: Path) -> bool:
        if not self.extensions and not self.filenames:
            return True
        name = path.name.lower()
        ext = path.suffix.lower()
        by_ext = bool(self.extensions and ext in self.extensions)
        by_name = bool(self.filenames and any(fnmatch.fnmatch(name, p) for p in self.filenames))
        return by_ext or by_name


@dataclass
class AuditFinding:
    rule_id: str
    title: str
    severity: str
    category: str
    path: str
    line: int
    column: int
    snippet: str
    remediation: str
    confidence: str = "medium"
    cwe: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "cwe": self.cwe,
        }


@dataclass
class AuditSummary:
    root: str
    scanned_files: int
    skipped_files: int
    findings_total: int
    counts: dict[str, int]
    score: int
    status: str
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "findings_total": self.findings_total,
            "counts": self.counts,
            "score": self.score,
            "status": self.status,
            "generated_at": self.generated_at,
        }


@dataclass
class AuditReport:
    summary: AuditSummary
    findings: list[AuditFinding]

    def to_dict(self) -> dict:
        return {
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }


def _rx(pattern: str, flags: int = re.IGNORECASE) -> Pattern[str]:
    return re.compile(pattern, flags)


def _rules() -> list[AuditRule]:
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
            "Add type allowlists and never deserialize user-controlled payloads into executable object graphs.",
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


def scan_project(
    root: str | os.PathLike[str],
    *,
    include_tests: bool = False,
    max_file_size: int = 512 * 1024,
) -> AuditReport:
    """Scan a file or repository and return a structured audit report."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")

    project_root = root_path.parent if root_path.is_file() else root_path
    rules = _rules()
    findings: list[AuditFinding] = []
    scanned = 0
    skipped = 0

    for path, was_skipped in _iter_candidate_files(root_path, include_tests, max_file_size):
        if was_skipped:
            skipped += 1
            continue
        try:
            text = _read_text(path)
        except UnicodeDecodeError:
            skipped += 1
            continue
        scanned += 1
        findings.extend(_scan_file(path, project_root, text, rules))

    if root_path.is_dir():
        findings.extend(_project_level_checks(project_root))

    findings = _dedupe_findings(findings)
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line, f.rule_id))
    counts = {sev: 0 for sev in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1

    score = max(0, 100 - sum(SEVERITY_SCORE[f.severity] for f in findings))
    status = "pass"
    if counts["CRITICAL"] or counts["HIGH"]:
        status = "fail"
    elif counts["MEDIUM"]:
        status = "review"

    summary = AuditSummary(
        root=str(root_path),
        scanned_files=scanned,
        skipped_files=skipped,
        findings_total=len(findings),
        counts=counts,
        score=score,
        status=status,
    )
    return AuditReport(summary=summary, findings=findings)


def should_fail(report: AuditReport, fail_on: str = "HIGH") -> bool:
    """Return True when the report should fail a delivery gate."""
    fail_on = (fail_on or "HIGH").upper()
    if fail_on in ("NONE", "NEVER", "OFF"):
        return False
    if fail_on not in SEVERITY_RANK:
        raise ValueError(f"Unsupported fail_on severity: {fail_on}")
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[f.severity] >= threshold for f in report.findings)


def render_report(report: AuditReport, fmt: str = "text", *, limit: int = 200) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if fmt == "markdown":
        return _render_markdown(report, limit=limit)
    if fmt == "sarif":
        return json.dumps(_to_sarif(report), indent=2, ensure_ascii=False)
    if fmt != "text":
        raise ValueError(f"Unsupported report format: {fmt}")
    return _render_text(report, limit=limit)


def _iter_candidate_files(
    root: Path,
    include_tests: bool,
    max_file_size: int,
) -> Iterable[tuple[Path, bool]]:
    if root.is_file():
        yield root, not _is_candidate(root, max_file_size)
        return

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORED_DIRS]
        for filename in filenames:
            path = current / filename
            rel = _rel(path, root)
            if not include_tests and _is_test_path(rel):
                continue
            yield path, not _is_candidate(path, max_file_size)


def _is_candidate(path: Path, max_file_size: int) -> bool:
    name = path.name.lower()
    if name.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar")):
        return False
    try:
        if path.stat().st_size > max_file_size:
            return False
    except OSError:
        return False
    if name in SPECIAL_FILENAMES or name.startswith(".env") or fnmatch.fnmatch(name, "dockerfile*"):
        return True
    if path.suffix.lower() in SOURCE_EXTENSIONS:
        return True
    return False


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    if b"\x00" in raw:
        raise UnicodeDecodeError("binary", raw, 0, 1, "NUL byte")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _scan_file(path: Path, project_root: Path, text: str, rules: list[AuditRule]) -> list[AuditFinding]:
    rel = _rel(path, project_root)
    findings: list[AuditFinding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:
            continue
        is_comment = _is_probable_comment(line, path.suffix.lower())
        for rule in rules:
            if not rule.matches_file(path):
                continue
            if is_comment and not rule.scan_comments:
                continue
            match = rule.pattern.search(line)
            if not match:
                continue
            if rule.validator and not _validate(rule.validator, match, line, path):
                continue
            severity = _effective_severity(rule, rel)
            findings.append(AuditFinding(
                rule_id=rule.id,
                title=rule.title,
                severity=severity,
                category=rule.category,
                path=rel,
                line=line_no,
                column=max(match.start() + 1, 1),
                snippet=_redact(line.strip()),
                remediation=rule.remediation,
                confidence=rule.confidence,
                cwe=rule.cwe,
            ))
    return findings


def _project_level_checks(root: Path) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    files = {p.name.lower(): p for p in root.iterdir() if p.is_file()}

    if not _has_tests(root):
        findings.append(_project_finding(
            "delivery-no-tests", "No test suite detected", "MEDIUM", "delivery",
            "Add unit or integration tests for generated code before delivery.",
            "No tests/, test/, spec/, or *_test source files were found.",
        ))

    package_jsons = list(root.rglob("package.json"))
    for package_json in package_jsons:
        if "node_modules" in package_json.parts:
            continue
        lock_names = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}
        if not any((package_json.parent / name).exists() for name in lock_names):
            findings.append(_project_finding(
                "delivery-node-lockfile", "Node project has no lockfile", "LOW", "supply-chain",
                "Commit a lockfile for reproducible deployable builds.",
                f"{_rel(package_json, root)} has no package lockfile beside it.",
                path=_rel(package_json, root),
            ))

    if "pyproject.toml" in files and not any(name in files for name in ("poetry.lock", "uv.lock", "pdm.lock")):
        findings.append(_project_finding(
            "delivery-python-lockfile", "Python project has no lockfile", "LOW", "supply-chain",
            "Generate and review a lockfile or compiled constraints for production builds.",
            "pyproject.toml exists without poetry.lock, uv.lock, or pdm.lock.",
            path="pyproject.toml",
        ))

    env_files = [name for name in files if name.startswith(".env") and name != ".env.example"]
    if env_files and ".env.example" not in files:
        findings.append(_project_finding(
            "delivery-env-example-missing", "Environment file committed without example template", "MEDIUM", "secrets",
            "Keep real .env files out of source and provide a sanitized .env.example template.",
            f"Found {', '.join(sorted(env_files))} but no .env.example.",
            path=sorted(env_files)[0],
        ))

    if not _has_ci(root):
        findings.append(_project_finding(
            "delivery-no-ci", "No CI workflow detected", "LOW", "delivery",
            "Add CI that runs tests, linting, and this security audit on every change.",
            "No common CI workflow file was found.",
        ))

    return findings


def _project_finding(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    remediation: str,
    snippet: str,
    *,
    path: str = ".",
) -> AuditFinding:
    return AuditFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        path=path,
        line=1,
        column=1,
        snippet=snippet,
        remediation=remediation,
        confidence="high",
    )


def _validate(name: str, match: re.Match[str], line: str, path: Path) -> bool:
    validators: dict[str, Validator] = {
        "secret_value": _validate_secret_value,
        "requirements_unpinned": _validate_requirements_unpinned,
        "docker_from_unpinned": _validate_docker_from_unpinned,
        "not_rule_definition": _validate_not_rule_definition,
        "placeholder_context": _validate_placeholder_context,
    }
    return validators[name](match, line, path)


def _validate_secret_value(match: re.Match[str], line: str, path: Path) -> bool:
    value = match.groupdict().get("value", "")
    lower = value.lower()
    if any(token in lower for token in (
        "example", "sample", "dummy", "placeholder", "changeme", "change_me",
        "your_", "insert_", "replace_me", "process.env", "os.environ",
    )):
        return False
    if value.startswith(("$", "${", "%", "{{")):
        return False
    has_alpha = any(c.isalpha() for c in value)
    has_other = any(c.isdigit() or not c.isalnum() for c in value)
    return len(value) >= 16 and has_alpha and has_other and _entropy(value) >= 3.0


def _validate_requirements_unpinned(match: re.Match[str], line: str, path: Path) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "-", "--")):
        return False
    if "://" in stripped or " @ " in stripped:
        return False
    return "==" not in stripped and "===" not in stripped


def _validate_docker_from_unpinned(match: re.Match[str], line: str, path: Path) -> bool:
    image = match.groupdict().get("image", "")
    if "@" in image:
        return False
    last_segment = image.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return True
    return last_segment.endswith(":latest")


def _validate_not_rule_definition(match: re.Match[str], line: str, path: Path) -> bool:
    stripped = line.strip()
    if path.name in {"ai_code_audit.py", "audit_code.py"}:
        if stripped.startswith(("r\"", "r'", "\"", "'")):
            return False
        if "for term in (" in stripped and any(
            term in stripped for term in ("temporary bypass", "placeholder", "not implemented")
        ):
            return False
    return "_rx(" not in stripped and "re.compile(" not in stripped and "AuditRule(" not in stripped


def _validate_placeholder_context(match: re.Match[str], line: str, path: Path) -> bool:
    if not _validate_not_rule_definition(match, line, path):
        return False
    stripped = line.strip()
    lower = stripped.lower()
    if _is_probable_comment(line, path.suffix.lower()):
        return True
    if any(marker in lower for marker in ("todo", "fixme", "hack")):
        return ("#" in stripped or "//" in stripped) and not stripped.startswith(("r\"", "r'", "\"", "'"))
    if "not implemented" in lower:
        return any(term in lower for term in ("raise", "throw", "panic", "return", "notimplemented"))
    if any(term in lower for term in ("temporary bypass", "for demo only", "replace in production")):
        return True
    if any(term in lower for term in ("dummy ", "placeholder ")):
        return any(term in lower for term in ("=", ":", "return", "const ", "let ", "var "))
    return False


def _effective_severity(rule: AuditRule, rel_path: str) -> str:
    if rule.sensitive_boost and SENSITIVE_PATH_RE.search(rel_path):
        rank = min(SEVERITY_RANK[rule.severity] + 1, SEVERITY_RANK["CRITICAL"])
        for severity, severity_rank in SEVERITY_RANK.items():
            if severity_rank == rank:
                return severity
    return rule.severity


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _is_probable_comment(line: str, ext: str) -> bool:
    stripped = line.lstrip()
    if not stripped:
        return False
    if stripped.startswith(("#", "//", "/*", "*", "<!--")):
        return True
    if ext in {".sql", ".lua"} and stripped.startswith("--"):
        return True
    return False


def _is_test_path(rel_path: str) -> bool:
    parts = {part.lower() for part in rel_path.replace("\\", "/").split("/")}
    if parts & TEST_PATH_PARTS:
        return True
    name = rel_path.rsplit("/", 1)[-1].lower()
    return (
        name.startswith("test_") or name.endswith("_test.py") or
        name.endswith(".test.js") or name.endswith(".test.ts") or
        name.endswith(".spec.js") or name.endswith(".spec.ts")
    )


def _has_tests(root: Path) -> bool:
    for candidate in ("tests", "test", "spec", "__tests__"):
        if (root / candidate).exists():
            return True
    for path in root.rglob("*"):
        if path.is_file() and _is_test_path(_rel(path, root)):
            return True
    return False


def _has_ci(root: Path) -> bool:
    ci_paths = [
        root / ".github" / "workflows",
        root / ".gitlab-ci.yml",
        root / "azure-pipelines.yml",
        root / ".circleci" / "config.yml",
        root / "Jenkinsfile",
    ]
    return any(path.exists() for path in ci_paths)


def _dedupe_findings(findings: list[AuditFinding]) -> list[AuditFinding]:
    seen: set[tuple[str, str, int, str]] = set()
    deduped: list[AuditFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line, finding.snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _redact(line: str) -> str:
    redacted = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}***redacted***{m.group(3)}", line)
    redacted = re.sub(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b", r"\1************", redacted)
    if len(redacted) > 240:
        redacted = redacted[:237] + "..."
    return redacted


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _render_text(report: AuditReport, *, limit: int) -> str:
    s = report.summary
    lines = [
        "AI Code Security Review",
        f"Root: {s.root}",
        f"Status: {s.status.upper()}  Score: {s.score}/100",
        f"Files: {s.scanned_files} scanned, {s.skipped_files} skipped",
        "Findings: " + ", ".join(f"{sev}={s.counts.get(sev, 0)}" for sev in SEVERITIES),
        "",
    ]
    if not report.findings:
        lines.append("No findings. The code passed the configured static delivery checks.")
        return "\n".join(lines)

    for finding in report.findings[:limit]:
        loc = f"{finding.path}:{finding.line}:{finding.column}"
        lines.extend([
            f"[{finding.severity}] {finding.rule_id} - {finding.title}",
            f"  at: {loc}",
            f"  evidence: {finding.snippet}",
            f"  fix: {finding.remediation}",
            "",
        ])
    if len(report.findings) > limit:
        lines.append(f"... {len(report.findings) - limit} more findings hidden by --limit")
    return "\n".join(lines).rstrip()


def _render_markdown(report: AuditReport, *, limit: int) -> str:
    s = report.summary
    lines = [
        "# AI Code Security Review",
        "",
        f"- **Status:** {s.status.upper()}",
        f"- **Score:** {s.score}/100",
        f"- **Files:** {s.scanned_files} scanned, {s.skipped_files} skipped",
        f"- **Findings:** " + ", ".join(f"{sev}={s.counts.get(sev, 0)}" for sev in SEVERITIES),
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for finding in report.findings[:limit]:
        lines.extend([
            f"### {finding.severity}: {finding.title}",
            "",
            f"- **Rule:** `{finding.rule_id}`",
            f"- **Location:** `{finding.path}:{finding.line}:{finding.column}`",
            f"- **Evidence:** `{finding.snippet}`",
            f"- **Fix:** {finding.remediation}",
            "",
        ])
    if len(report.findings) > limit:
        lines.append(f"_Hidden findings: {len(report.findings) - limit}_")
    return "\n".join(lines).rstrip()


def _to_sarif(report: AuditReport) -> dict:
    rules_by_id: dict[str, AuditFinding] = {}
    for finding in report.findings:
        rules_by_id.setdefault(finding.rule_id, finding)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AI Code Security Review",
                    "rules": [
                        {
                            "id": rule_id,
                            "name": f.title,
                            "shortDescription": {"text": f.title},
                            "help": {"text": f.remediation},
                            "properties": {
                                "category": f.category,
                                "severity": f.severity,
                                "confidence": f.confidence,
                                "cwe": f.cwe,
                            },
                        }
                        for rule_id, f in sorted(rules_by_id.items())
                    ],
                }
            },
            "results": [
                {
                    "ruleId": f.rule_id,
                    "level": _sarif_level(f.severity),
                    "message": {"text": f"{f.title}: {f.snippet}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": f.line, "startColumn": f.column},
                        }
                    }],
                    "properties": {
                        "severity": f.severity,
                        "category": f.category,
                        "confidence": f.confidence,
                        "remediation": f.remediation,
                    },
                }
                for f in report.findings
            ],
        }],
    }


def _sarif_level(severity: str) -> str:
    if severity in ("CRITICAL", "HIGH"):
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline security readiness checks for AI-generated code."
    )
    parser.add_argument("path", help="Repository, directory, or file to scan.")
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "sarif"),
        default="text",
        help="Report format. Default: text.",
    )
    parser.add_argument(
        "--output",
        help="Write the report to this file instead of stdout.",
    )
    parser.add_argument(
        "--fail-on",
        default="HIGH",
        help="Fail when findings at or above this severity exist, or use 'none'. Default: HIGH.",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include tests, fixtures, examples, and specs.",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=512 * 1024,
        help="Skip files larger than this many bytes. Default: 524288.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Maximum findings rendered in text or markdown reports. Default: 200.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = scan_project(
            args.path,
            include_tests=args.include_tests,
            max_file_size=args.max_file_size,
        )
        output = render_report(report, args.format, limit=args.limit)
        if args.output:
            Path(args.output).expanduser().write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 1 if should_fail(report, args.fail_on) else 0
    except Exception as exc:
        print(f"audit_code.py: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

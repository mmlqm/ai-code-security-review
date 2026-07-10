#!/usr/bin/env python3
"""
audit_code.py - offline security readiness checks for AI-generated code.

The scanner is intentionally deterministic and stdlib-only so it can run in CI
before AI-authored code is accepted for delivery. It looks for patterns that are
common in generated code: hardcoded secrets, auth placeholders, insecure defaults,
injection sinks, weak crypto, unsafe deserialization, permissive deployment
settings, and dependency hygiene gaps.

This script is packaged for a Codex skill. It performs local static review only:
no live-service testing or network probing.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Pattern

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None

# ── Optional: enhanced redaction ─────────────────────────────────────
try:
    from redact import redact_line as _redact_enhanced
    from redact import detect_high_entropy_strings, detect_yaml_secrets
    _HAS_ENHANCED_REDACT = True
except ImportError:
    _HAS_ENHANCED_REDACT = False

# ── Optional: regex sandbox for custom rules ─────────────────────────
try:
    from auditors.regex_sandbox import safe_compile_custom_rule
    _HAS_REGEX_SANDBOX = True
except ImportError:
    _HAS_REGEX_SANDBOX = False

# ── Optional: variable tracking ──────────────────────────────────────
try:
    from auditors.variable_tracker import scan_file_for_tracked_variables, TRACK_RULES
    _HAS_VARIABLE_TRACKER = True
except ImportError:
    _HAS_VARIABLE_TRACKER = False


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
    ".xml", ".html", ".gradle", ".properties", ".env", ".tf", ".hcl",
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

PY_ASSIGN_RE = re.compile(r"^\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>.+)$")
PY_SQL_KEYWORD_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|WITH)\b", re.IGNORECASE)
PY_DYNAMIC_SQL_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_])f[\"'][^\"']*\{[^\"']*\}[^\"']*[\"']|"
    r"[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|WITH)\b[^\"']*[\"']\s*(?:%|\+|\.format\s*\()|"
    r"(?:request\.|args\.get|form\.get|input\s*\(|params|query)"
)
PY_SHELL_BUILD_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_])f[\"'][^\"']*\{[^\"']*\}[^\"']*[\"']|"
    r"[\"'][^\"']*[\"']\s*(?:%|\+|\.format\s*\()|"
    r"(?:request\.|args\.get|form\.get|input\s*\(|params|query)"
)

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|"
    r"private[_-]?key|access[_-]?key)\b\s*[:=]\s*[\"'])([^\"']+)([\"'])"
)

CONFIG_FILENAMES = (".audit-code.toml", "audit-code.toml")
AUDITIGNORE_FILENAME = ".auditignore"
SUPPRESS_RE = re.compile(r"audit-code:\s*(ignore|ignore-next-line)(?:\s+([^#/\r\n]+))?", re.IGNORECASE)
RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{1,96}$")
ANSI_COLORS = {
    "CRITICAL": "\033[95m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
    "PASS": "\033[92m",
    "REVIEW": "\033[93m",
    "FAIL": "\033[91m",
    "RESET": "\033[0m",
}


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
    origin: str = "builtin"
    scan_mode: str = "line"
    window_lines: int = 1

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
    fingerprint: str = ""

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
            "fingerprint": self.fingerprint,
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
    suppressed_findings: int = 0
    baseline_findings: int = 0
    long_lines_skipped: int = 0
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
            "suppressed_findings": self.suppressed_findings,
            "baseline_findings": self.baseline_findings,
            "long_lines_skipped": self.long_lines_skipped,
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


@dataclass
class AuditConfig:
    include_tests: bool = False
    max_file_size: int = 512 * 1024
    fail_on: str = "HIGH"
    disabled_rules: set[str] = field(default_factory=set)
    exclude: tuple[str, ...] = ()
    baseline: str = ""
    custom_rules: list[AuditRule] = field(default_factory=list)
    config_path: str = ""


def _rx(pattern: str, flags: int = re.IGNORECASE) -> Pattern[str]:
    return re.compile(pattern, flags)


def _rules() -> list[AuditRule]:
    """Rule catalog tuned for generated application code and delivery gates."""
    from rules_builtin import builtin_rules

    return builtin_rules(AuditRule, _rx)

def _load_config(
    project_root: Path,
    config_path: str | os.PathLike[str] | None,
    *,
    no_config: bool = False,
) -> AuditConfig:
    if no_config:
        return AuditConfig()
    path: Path | None = Path(config_path).expanduser() if config_path else None
    if path is None:
        for filename in CONFIG_FILENAMES:
            candidate = project_root / filename
            if candidate.exists():
                path = candidate
                break
    if path is None:
        return AuditConfig()
    if tomllib is None:
        raise RuntimeError("TOML config requires Python 3.11+ tomllib")
    if not path.exists():
        raise FileNotFoundError(f"Config file does not exist: {path}")

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    settings = data.get("settings", {})
    if settings and not isinstance(settings, dict):
        raise ValueError("[settings] must be a table")

    config = AuditConfig(config_path=str(path))
    if "include_tests" in settings:
        config.include_tests = bool(settings["include_tests"])
    if "max_file_size" in settings:
        config.max_file_size = _as_int(settings["max_file_size"], "settings.max_file_size")
    if "fail_on" in settings:
        config.fail_on = _as_severity_or_none(settings["fail_on"], "settings.fail_on")
    if "disabled_rules" in settings:
        config.disabled_rules = set(_as_str_list(settings["disabled_rules"], "settings.disabled_rules"))
    if "exclude" in settings:
        config.exclude = tuple(_as_str_list(settings["exclude"], "settings.exclude"))
    if "baseline" in settings:
        config.baseline = str(settings["baseline"])

    raw_rules = data.get("rules", [])
    if raw_rules and not isinstance(raw_rules, list):
        raise ValueError("[[rules]] must be an array of tables")
    config.custom_rules = [_rule_from_config(rule, path, index + 1) for index, rule in enumerate(raw_rules)]
    return config


def _rule_from_config(raw: Any, config_path: Path, index: int) -> AuditRule:
    if not isinstance(raw, dict):
        raise ValueError(f"rules[{index}] must be a table")
    required = ("id", "title", "severity", "category", "pattern", "remediation")
    missing = [field_name for field_name in required if not raw.get(field_name)]
    if missing:
        raise ValueError(f"{config_path}: rules[{index}] missing required fields: {', '.join(missing)}")

    rule_id = str(raw["id"]).strip()
    if not RULE_ID_RE.match(rule_id):
        raise ValueError(f"{config_path}: rules[{index}].id is invalid: {rule_id}")
    severity = _as_severity(raw["severity"], f"rules[{index}].severity")
    ignore_case = bool(raw.get("ignore_case", True))
    anchors_cross_lines = bool(raw.get("anchors_cross_lines", False))
    if raw.get("multiline"):
        print(
            "Warning: 'multiline' is deprecated; use 'anchors_cross_lines'. "
            "For multi-line content matching use scan_mode = 'file' or 'sliding_window'.",
            file=sys.stderr,
        )
        anchors_cross_lines = True
    dotall = bool(raw.get("dotall", False))
    scan_mode = str(raw.get("scan_mode", "line")).lower()
    if scan_mode not in {"line", "file", "sliding_window"}:
        raise ValueError(f"{config_path}: rules[{index}].scan_mode must be line, file, or sliding_window")
    window_lines = _as_int(raw.get("window_lines", 5), f"rules[{index}].window_lines")
    if window_lines < 1:
        raise ValueError(f"{config_path}: rules[{index}].window_lines must be >= 1")
    flags = 0
    if ignore_case:
        flags |= re.IGNORECASE
    if anchors_cross_lines:
        flags |= re.MULTILINE
    if dotall:
        flags |= re.DOTALL
    pattern_str = str(raw["pattern"])
    try:
        if _HAS_REGEX_SANDBOX:
            pattern = safe_compile_custom_rule(pattern_str, flags, rule_id=rule_id)
        else:
            # Basic ReDoS guard: estimate complexity, warn if high
            complexity = (
                pattern_str.count("*") * 3 + pattern_str.count("+") * 3 +
                pattern_str.count("{") * 2 + pattern_str.count("|") * 2
            )
            if complexity > 40:
                raise ValueError(
                    f"{config_path}: rules[{index}].pattern is too complex (score={complexity}). "
                    f"Simplify or split into multiple rules with more specific patterns."
                )
            pattern = re.compile(pattern_str, flags)
    except re.error as exc:
        raise ValueError(f"{config_path}: rules[{index}].pattern is not valid regex: {exc}") from exc

    return AuditRule(
        id=rule_id,
        title=str(raw["title"]),
        severity=severity,
        category=str(raw["category"]),
        pattern=pattern,
        remediation=str(raw["remediation"]),
        cwe=str(raw.get("cwe", "")),
        confidence=str(raw.get("confidence", "medium")),
        extensions=tuple(ext.lower() for ext in _as_str_list(raw.get("extensions", []), f"rules[{index}].extensions")),
        filenames=tuple(name.lower() for name in _as_str_list(raw.get("filenames", []), f"rules[{index}].filenames")),
        scan_comments=bool(raw.get("scan_comments", False)),
        sensitive_boost=bool(raw.get("sensitive_boost", False)),
        origin="custom",
        scan_mode=scan_mode,
        window_lines=window_lines,
    )


def _as_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer") from exc


def _as_severity(value: Any, label: str) -> str:
    severity = str(value).upper()
    if severity not in SEVERITY_RANK:
        raise ValueError(f"{label} must be one of {', '.join(SEVERITIES)}")
    return severity


def _as_severity_or_none(value: Any, label: str) -> str:
    severity = str(value).upper()
    if severity in ("NONE", "NEVER", "OFF"):
        return severity
    return _as_severity(severity, label)


def _as_str_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a string or list of strings")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{label} must contain only strings")
        items.append(item)
    return items


def _load_baseline(path: Path, project_root: Path) -> set[str]:
    resolved = path if path.is_absolute() else project_root / path
    if not resolved.exists():
        raise FileNotFoundError(f"Baseline file does not exist: {resolved}")
    data = json.loads(resolved.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        fingerprints = data.get("fingerprints")
        if fingerprints is None:
            fingerprints = [finding.get("fingerprint") for finding in data.get("findings", []) if isinstance(finding, dict)]
    elif isinstance(data, list):
        fingerprints = data
    else:
        raise ValueError("Baseline must be a JSON object or list")
    return {str(fingerprint) for fingerprint in fingerprints if fingerprint}


def _load_auditignore(project_root: Path) -> list[str]:
    path = project_root / AUDITIGNORE_FILENAME
    if not path.exists():
        return []
    patterns: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            continue
        if line.endswith("/"):
            line = line + "**"
        patterns.append(line)
    return patterns


def write_baseline(report: AuditReport, path: str | os.PathLike[str]) -> None:
    payload = {
        "version": 1,
        "generated_at": time.time(),
        "fingerprints": sorted({finding.fingerprint for finding in report.findings if finding.fingerprint}),
        "findings": [finding.to_dict() for finding in report.findings],
    }
    Path(path).expanduser().write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _all_rules(config: AuditConfig | None = None) -> list[AuditRule]:
    config = config or AuditConfig()
    return [rule for rule in (_rules() + config.custom_rules) if rule.id not in config.disabled_rules]


def scan_project(
    root: str | os.PathLike[str],
    *,
    include_tests: bool = False,
    max_file_size: int = 512 * 1024,
    config_path: str | os.PathLike[str] | None = None,
    no_config: bool = False,
    disabled_rules: Iterable[str] = (),
    exclude: Iterable[str] = (),
    baseline: str | os.PathLike[str] | None = None,
    changed_paths: Iterable[str] = (),
) -> AuditReport:
    """Scan a file or repository and return a structured audit report."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")

    project_root = root_path.parent if root_path.is_file() else root_path
    config = _load_config(project_root, config_path, no_config=no_config)
    include_tests = bool(include_tests or config.include_tests)
    if max_file_size == 512 * 1024 and config.max_file_size:
        max_file_size = config.max_file_size
    disabled = set(config.disabled_rules) | {rule_id for rule_id in disabled_rules}
    excludes = tuple(config.exclude) + tuple(_load_auditignore(project_root)) + tuple(exclude)
    rules = [rule for rule in (_rules() + config.custom_rules) if rule.id not in disabled]
    baseline_path = Path(baseline).expanduser() if baseline else (Path(config.baseline).expanduser() if config.baseline else None)
    baseline_fingerprints = _load_baseline(baseline_path, project_root) if baseline_path else set()
    if baseline_path:
        resolved_baseline = (baseline_path if baseline_path.is_absolute() else project_root / baseline_path).resolve()
        try:
            excludes = excludes + (resolved_baseline.relative_to(project_root).as_posix(),)
        except ValueError:
            pass
    findings: list[AuditFinding] = []
    scanned = 0
    skipped = 0
    suppressed = 0
    long_lines_skipped = 0

    for path, was_skipped in _iter_candidate_files(
        root_path, include_tests, max_file_size, excludes, changed_paths
    ):
        if was_skipped:
            skipped += 1
            continue
        try:
            text = _read_text(path)
        except UnicodeDecodeError:
            skipped += 1
            continue
        scanned += 1
        file_findings, file_suppressed, file_long_lines = _scan_file(path, project_root, text, rules)
        findings.extend(file_findings)
        suppressed += file_suppressed
        long_lines_skipped += file_long_lines

    if root_path.is_dir():
        findings.extend(_project_level_checks(project_root))

    findings = _dedupe_findings(findings)
    baseline_count = 0
    if baseline_fingerprints:
        kept: list[AuditFinding] = []
        for finding in findings:
            if finding.fingerprint in baseline_fingerprints:
                baseline_count += 1
                continue
            kept.append(finding)
        findings = kept
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
        suppressed_findings=suppressed,
        baseline_findings=baseline_count,
        long_lines_skipped=long_lines_skipped,
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


def render_report(report: AuditReport, fmt: str = "text", *, limit: int = 200, color: bool = False) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if fmt == "markdown":
        return _render_markdown(report, limit=limit)
    if fmt == "sarif":
        return json.dumps(_to_sarif(report), indent=2, ensure_ascii=False)
    if fmt != "text":
        raise ValueError(f"Unsupported report format: {fmt}")
    return _render_text(report, limit=limit, color=color)


def _iter_candidate_files(
    root: Path,
    include_tests: bool,
    max_file_size: int,
    exclude: Iterable[str] = (),
    changed_paths: Iterable[str] = (),
) -> Iterable[tuple[Path, bool]]:
    exclude_patterns = tuple(exclude)
    changed = [item.strip() for item in changed_paths if item and item.strip()]
    if changed and root.is_dir():
        for rel in changed:
            rel = rel.replace("\\", "/").lstrip("/")
            path = (root / rel).resolve()
            try:
                normalized = path.relative_to(root).as_posix()
            except ValueError:
                yield path, True
                continue
            if not path.exists() or not path.is_file():
                yield path, True
                continue
            if _matches_any_glob(normalized, exclude_patterns):
                yield path, True
                continue
            if not include_tests and _is_test_path(normalized):
                continue
            yield path, not _is_candidate(path, max_file_size)
        return

    if root.is_file():
        yield root, not _is_candidate(root, max_file_size)
        return

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORED_DIRS]
        for filename in filenames:
            path = current / filename
            rel = _rel(path, root)
            if _matches_any_glob(rel, exclude_patterns):
                yield path, True
                continue
            if not include_tests and _is_test_path(rel):
                continue
            yield path, not _is_candidate(path, max_file_size)


def _is_candidate(path: Path, max_file_size: int) -> bool:
    name = path.name.lower()
    if name in {".audit-baseline.json", "audit-baseline.json", "ai-code-security-baseline.json"}:
        return False
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


def _matches_any_glob(rel_path: str, patterns: Iterable[str]) -> bool:
    normalized = rel_path.replace("\\", "/")
    for pattern in patterns:
        pat = pattern.replace("\\", "/")
        if fnmatch.fnmatch(normalized, pat) or fnmatch.fnmatch(Path(normalized).name, pat):
            return True
    return False


def _parse_suppressions(line: str) -> tuple[set[str], set[str]]:
    current: set[str] = set()
    next_line: set[str] = set()
    for match in SUPPRESS_RE.finditer(line):
        target = current if match.group(1).lower() == "ignore" else next_line
        raw_rules = (match.group(2) or "*").strip()
        if not raw_rules:
            raw_rules = "*"
        for token in re.split(r"[\s,]+", raw_rules):
            token = token.strip()
            if token:
                target.add(token)
    return current, next_line


def _is_suppressed(rule_id: str, suppressions: set[str]) -> bool:
    return "*" in suppressions or "all" in suppressions or rule_id in suppressions


def _fingerprint(finding: AuditFinding) -> str:
    material = f"{finding.rule_id}\0{finding.path}\0{finding.snippet}"
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:20]


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    if b"\x00" in raw:
        raise UnicodeDecodeError("binary", raw, 0, 1, "NUL byte")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _scan_file(path: Path, project_root: Path, text: str, rules: list[AuditRule]) -> tuple[list[AuditFinding], int, int]:
    rel = _rel(path, project_root)
    findings: list[AuditFinding] = []
    suppressed = 0
    long_lines_skipped = 0
    next_line_suppressions: dict[int, set[str]] = {}
    lines = text.splitlines()
    line_rules = [rule for rule in rules if rule.scan_mode == "line"]
    content_rules = [rule for rule in rules if rule.scan_mode in {"file", "sliding_window"}]

    for line_no, line in enumerate(lines, 1):
        if len(line) > 5000:
            long_lines_skipped += 1
            continue
        current_suppressions = set(next_line_suppressions.pop(line_no, set()))
        line_suppressions, next_suppressions = _parse_suppressions(line)
        current_suppressions.update(line_suppressions)
        if next_suppressions:
            next_line_suppressions.setdefault(line_no + 1, set()).update(next_suppressions)
        is_comment = _is_probable_comment(line, path.suffix.lower())
        for rule in line_rules:
            if not rule.matches_file(path):
                continue
            if is_comment and not rule.scan_comments:
                continue
            match = rule.pattern.search(line)
            if not match:
                continue
            if rule.validator and not _validate(rule.validator, match, line, path):
                continue
            if _is_suppressed(rule.id, current_suppressions):
                suppressed += 1
                continue
            severity = _effective_severity(rule, rel)
            snippet = _redact(line.strip())
            findings.append(
                _make_finding(
                    rule=rule,
                    rel=rel,
                    line_no=line_no,
                    column=max(match.start() + 1, 1),
                    snippet=snippet,
                    severity=severity,
                )
            )

    for rule in content_rules:
        if not rule.matches_file(path):
            continue
        for match, window_start, window_text in _iter_content_matches(rule, text, lines):
            line_no = window_start + window_text[:match.start()].count("\n")
            line_text = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
            suppressions, _ = _parse_suppressions(line_text)
            if _is_suppressed(rule.id, suppressions):
                suppressed += 1
                continue
            raw_snippet = match.group(0).replace("\r", " ").replace("\n", " ")
            snippet = _redact(raw_snippet.strip())
            severity = _effective_severity(rule, rel)
            findings.append(
                _make_finding(
                    rule=rule,
                    rel=rel,
                    line_no=line_no,
                    column=max(_column_for_offset(window_text, match.start()) + 1, 1),
                    snippet=snippet,
                    severity=severity,
                )
            )

    if long_lines_skipped:
        finding = AuditFinding(
            rule_id="scan-long-lines-skipped",
            title=f"{long_lines_skipped} long lines skipped",
            severity="INFO",
            category="scan-limitation",
            path=rel,
            line=1,
            column=1,
            snippet=f"{long_lines_skipped} lines longer than 5000 characters were not scanned.",
            remediation="Scan the unminified source or reduce generated/bundled line length.",
            confidence="high",
        )
        finding.fingerprint = _fingerprint(finding)
        findings.append(finding)

    tracked_findings, tracked_suppressed = _scan_tracked_variables(path, rel, lines, rules)
    findings.extend(tracked_findings)
    suppressed += tracked_suppressed

    # ── High-entropy string detection ──
    if _HAS_ENHANCED_REDACT:
        for hs in detect_high_entropy_strings(text):
            hfinding = AuditFinding(
                rule_id="secret-high-entropy",
                title=f"High-entropy string ({hs['entropy']} bits, {hs['length']} chars)",
                severity="MEDIUM",
                category="secrets",
                path=rel,
                line=1,
                column=hs["position"] + 1,
                snippet=f"[HASH:{hs['hash_prefix']}] len={hs['length']} entropy={hs['entropy']}",
                remediation="Verify this is not a hardcoded credential. If it is, move to a secret manager and rotate it.",
                confidence="low",
            )
            hfinding.fingerprint = _fingerprint(hfinding)
            findings.append(hfinding)

        for ys in detect_yaml_secrets(text):
            yfinding = AuditFinding(
                rule_id="secret-yaml-unquoted",
                title=f"Unquoted secret-like value in YAML/TOML: {ys['key']}",
                severity="MEDIUM",
                category="secrets",
                path=rel,
                line=ys["line"],
                column=1,
                snippet=f"{ys['key']}: [REDACTED - {ys['value_length']} chars]",
                remediation="Ensure this value is loaded from an environment variable or secret manager, not hardcoded.",
                confidence="low",
            )
            yfinding.fingerprint = _fingerprint(yfinding)
            findings.append(yfinding)

    return findings, suppressed, long_lines_skipped


def _scan_tracked_variables(
    path: Path,
    rel: str,
    lines: list[str],
    rules: list[AuditRule],
) -> tuple[list[AuditFinding], int]:
    if path.suffix.lower() != ".py":
        return [], 0
    rule_by_id = {rule.id: rule for rule in rules}
    sql_rule = rule_by_id.get("sql-python-variable-track")
    shell_rule = rule_by_id.get("shell-python-variable-track")
    if not sql_rule and not shell_rule:
        return [], 0

    tracked: dict[str, tuple[AuditRule, int, str]] = {}
    findings: list[AuditFinding] = []
    suppressed = 0
    for line_no, line in enumerate(lines, 1):
        if len(line) > 5000 or _is_probable_comment(line, path.suffix.lower()):
            continue
        suppressions, _ = _parse_suppressions(line)
        assignment = PY_ASSIGN_RE.match(line)
        if assignment:
            var_name = assignment.group("var")
            expr = assignment.group("expr")
            tracked.pop(var_name, None)
            if sql_rule and _is_dynamic_sql_assignment(expr):
                tracked[var_name] = (sql_rule, line_no, line.strip())
            elif shell_rule and _is_shell_command_assignment(var_name, expr):
                tracked[var_name] = (shell_rule, line_no, line.strip())
            continue
        for var_name, (rule, source_line, source_snippet) in list(tracked.items()):
            if not _tracked_variable_reaches_sink(var_name, rule.id, line):
                continue
            if _is_suppressed(rule.id, suppressions):
                suppressed += 1
                continue
            snippet = _redact(f"{line.strip()}  # {var_name} assigned at line {source_line}: {source_snippet}")
            findings.append(
                _make_finding(
                    rule=rule,
                    rel=rel,
                    line_no=line_no,
                    column=max(line.find(var_name) + 1, 1),
                    snippet=snippet,
                    severity=_effective_severity(rule, rel),
                )
            )
    return findings, suppressed


def _is_dynamic_sql_assignment(expr: str) -> bool:
    return bool(PY_SQL_KEYWORD_RE.search(expr) and PY_DYNAMIC_SQL_RE.search(expr))


def _is_shell_command_assignment(var_name: str, expr: str) -> bool:
    lower = expr.lower()
    var_lower = var_name.lower()
    looks_like_command = var_lower in {"cmd", "command", "shell_cmd", "shell_command"} or any(
        token in lower for token in ("shlex", "subprocess", "os.system", "popen", "cmd", "command")
    )
    if not looks_like_command:
        return False
    return bool(PY_SHELL_BUILD_RE.search(expr))


def _tracked_variable_reaches_sink(var_name: str, rule_id: str, line: str) -> bool:
    escaped = re.escape(var_name)
    if rule_id == "sql-python-variable-track":
        return bool(re.search(rf"\.execute(?:many)?\s*\(\s*{escaped}\b", line))
    if rule_id == "shell-python-variable-track":
        return bool(re.search(rf"\b(?:os\.system|os\.popen|subprocess\.[A-Za-z_]+|commands\.getoutput)\s*\(\s*{escaped}\b", line))
    return False


def _iter_content_matches(
    rule: AuditRule,
    text: str,
    lines: list[str],
) -> Iterable[tuple[re.Match[str], int, str]]:
    if rule.scan_mode == "file":
        for match in rule.pattern.finditer(text):
            yield match, 1, text
        return

    if rule.scan_mode == "sliding_window":
        window = max(rule.window_lines, 1)
        for start_index in range(0, len(lines)):
            chunk = "\n".join(lines[start_index:start_index + window])
            if not chunk:
                continue
            for match in rule.pattern.finditer(chunk):
                yield match, start_index + 1, chunk


def _column_for_offset(text: str, offset: int) -> int:
    previous_newline = text.rfind("\n", 0, offset)
    if previous_newline == -1:
        return offset
    return offset - previous_newline - 1


def _make_finding(
    *,
    rule: AuditRule,
    rel: str,
    line_no: int,
    column: int,
    snippet: str,
    severity: str,
) -> AuditFinding:
    finding = AuditFinding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity,
        category=rule.category,
        path=rel,
        line=line_no,
        column=column,
        snippet=snippet,
        remediation=rule.remediation,
        confidence=rule.confidence,
        cwe=rule.cwe,
    )
    finding.fingerprint = _fingerprint(finding)
    return finding


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
    finding = AuditFinding(
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
    finding.fingerprint = _fingerprint(finding)
    return finding


def _validate(name: str, match: re.Match[str], line: str, path: Path) -> bool:
    validators: dict[str, Validator] = {
        "secret_value": _validate_secret_value,
        "secret_entropy_value": _validate_secret_entropy_value,
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


def _validate_secret_entropy_value(match: re.Match[str], line: str, path: Path) -> bool:
    value = match.groupdict().get("value", "")
    lower = value.lower()
    if not value or len(value) < 32:
        return False
    if any(token in lower for token in (
        "example", "sample", "dummy", "placeholder", "changeme", "your",
        "aaaaaaaa", "bbbbbbbb", "cccccccc", "00000000", "11111111",
    )):
        return False
    if any(marker in line.lower() for marker in ("sha256", "sha512", "integrity", "checksum", "fingerprint")):
        return False
    if value.startswith(("data:image/", "-----begin")):
        return False
    if re.fullmatch(r"[0-9a-fA-F]{32,}", value):
        return False
    has_alpha = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_alpha and has_digit and _entropy(value) >= 4.2


def _validate_requirements_unpinned(match: re.Match[str], line: str, path: Path) -> bool:
    stripped = line.strip()
    if "#" in stripped:
        stripped = stripped.split("#", 1)[0].strip()
    if not stripped or stripped.startswith(("-", "--")):
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
    if path.name in {"ai_code_audit.py", "audit_code.py", "rules_builtin.py"}:
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
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORED_DIRS]
        current = Path(dirpath)
        for filename in filenames:
            if _is_test_path(_rel(current / filename, root)):
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
    # Use enhanced redaction if available (covers GitHub PAT, GitLab tokens, JWT, etc.)
    if _HAS_ENHANCED_REDACT:
        result = _redact_enhanced(line)
        if len(result) > 240:
            result = result[:237] + "..."
        return result
    # Fallback: basic redaction
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


def _safe_write_path(user_path: str, project_root: Path, label: str) -> None:
    """Warn if the output path is outside the project root, but don't block."""
    resolved = Path(user_path).expanduser().resolve()
    try:
        resolved.relative_to(project_root.resolve())
    except ValueError:
        print(
            f"Warning: {label} path '{user_path}' resolves outside the project root "
            f"({project_root}). This is allowed but double-check the destination.",
            file=sys.stderr,
        )


def _paint(text: str, key: str, enabled: bool) -> str:
    if not enabled:
        return text
    color = ANSI_COLORS.get(key, "")
    reset = ANSI_COLORS["RESET"] if color else ""
    return f"{color}{text}{reset}"


def _render_text(report: AuditReport, *, limit: int, color: bool = False) -> str:
    s = report.summary
    status = s.status.upper()
    lines = [
        "AI Code Security Review",
        f"Root: {s.root}",
        f"Status: {_paint(status, status, color)}  Score: {s.score}/100",
        f"Files: {s.scanned_files} scanned, {s.skipped_files} skipped",
        "Findings: " + ", ".join(f"{sev}={s.counts.get(sev, 0)}" for sev in SEVERITIES),
        f"Suppressed: {s.suppressed_findings}  Baseline-filtered: {s.baseline_findings}  Long-lines-skipped: {s.long_lines_skipped}",
        "",
    ]
    if not report.findings:
        lines.append("No findings. The code passed the configured static delivery checks.")
        return "\n".join(lines)

    for finding in report.findings[:limit]:
        loc = f"{finding.path}:{finding.line}:{finding.column}"
        lines.extend([
            f"[{_paint(finding.severity, finding.severity, color)}] {finding.rule_id} - {finding.title}",
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
        f"- **Suppressed:** {s.suppressed_findings}",
        f"- **Baseline-filtered:** {s.baseline_findings}",
        f"- **Long-lines-skipped:** {s.long_lines_skipped}",
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
            f"- **Fingerprint:** `{finding.fingerprint}`",
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
                        "fingerprint": f.fingerprint,
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


def render_rules(rules: list[AuditRule], fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps([
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "category": rule.category,
                "confidence": rule.confidence,
                "cwe": rule.cwe,
                "origin": rule.origin,
                "scan_mode": rule.scan_mode,
                "window_lines": rule.window_lines,
                "extensions": list(rule.extensions),
                "filenames": list(rule.filenames),
                "scan_comments": rule.scan_comments,
            }
            for rule in sorted(rules, key=lambda item: (item.origin, item.id))
        ], indent=2, ensure_ascii=False)
    lines = ["AI Code Security Review Rules", ""]
    for rule in sorted(rules, key=lambda item: (item.origin, item.id)):
        scope = []
        if rule.extensions:
            scope.append("extensions=" + ",".join(rule.extensions))
        if rule.filenames:
            scope.append("filenames=" + ",".join(rule.filenames))
        if rule.scan_mode != "line":
            scope.append(f"scan_mode={rule.scan_mode}")
            if rule.scan_mode == "sliding_window":
                scope.append(f"window_lines={rule.window_lines}")
        scope_text = f" ({'; '.join(scope)})" if scope else ""
        lines.append(f"[{rule.severity}] {rule.id} - {rule.title} [{rule.origin}]{scope_text}")
    return "\n".join(lines)


def render_github_annotations(report: AuditReport, *, limit: int = 200) -> str:
    lines: list[str] = []
    for finding in report.findings[:limit]:
        level = "error" if finding.severity in ("CRITICAL", "HIGH") else "warning" if finding.severity == "MEDIUM" else "notice"
        title = _gha_escape(f"{finding.severity} {finding.rule_id}")
        message = _gha_escape(f"{finding.title}: {finding.remediation}")
        file_name = _gha_escape(finding.path)
        lines.append(
            f"::{level} file={file_name},line={finding.line},col={finding.column},title={title}::{message}"
        )
    return "\n".join(lines)


def _gha_escape(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _write_sample_config(path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"Config already exists: {path}")
    path.write_text(
        """# AI Code Security Review configuration

[settings]
fail_on = "HIGH"
include_tests = false
max_file_size = 524288
disabled_rules = []
exclude = [
  "dist/**",
  "build/**",
  "generated/**",
]

# Example team policy rule. Duplicate this block and adjust it for local rules.
[[rules]]
id = "policy-no-dangerous-library"
title = "Disallowed dependency or library"
severity = "MEDIUM"
category = "policy"
pattern = "\\bexample-dangerous-library\\b"
remediation = "Replace this library with the approved project alternative."
filenames = ["requirements*.txt", "package.json", "pyproject.toml"]
scan_comments = false
confidence = "medium"
""",
        encoding="utf-8",
    )


def _load_changed_paths(args: argparse.Namespace) -> list[str]:
    changed = list(args.changed_files or [])
    if args.changed_files_from:
        path = Path(args.changed_files_from).expanduser()
        changed.extend(path.read_text(encoding="utf-8").splitlines())
    return [item.strip() for item in changed if item and item.strip()]


def _use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline security readiness checks for AI-generated code."
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository, directory, or file to scan. Default: current directory.")
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
        help="Fail when findings at or above this severity exist, or use 'none'. Default: config or HIGH.",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include tests, fixtures, examples, and specs.",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        help="Skip files larger than this many bytes. Default: config or 524288.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Maximum findings rendered in text or markdown reports. Default: 200.",
    )
    parser.add_argument("--config", help="Path to .audit-code.toml. Defaults to auto-discovery in the scanned root.")
    parser.add_argument("--no-config", action="store_true", help="Disable .audit-code.toml auto-discovery.")
    parser.add_argument("--disable-rule", action="append", default=[], help="Disable a rule by id. Can be repeated.")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude paths by glob. Can be repeated.")
    parser.add_argument("--baseline", help="Filter findings already present in a baseline JSON file.")
    parser.add_argument("--write-baseline", help="Write current findings to a baseline JSON file.")
    parser.add_argument("--changed-files", nargs="*", default=[], help="Scan only these changed paths relative to the root.")
    parser.add_argument("--changed-files-from", help="Read newline-delimited changed paths from a file.")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Colorize text output. Default: auto.",
    )
    parser.add_argument("--github-annotations", action="store_true", help="Emit GitHub Actions annotation commands for findings.")
    parser.add_argument("--list-rules", action="store_true", help="List active rules and exit. Use --format json for machine output.")
    parser.add_argument("--init-config", action="store_true", help="Write a starter .audit-code.toml in the scanned root and exit.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        root_path = Path(args.path).expanduser().resolve()
        project_root = root_path.parent if root_path.is_file() else root_path
        if args.init_config:
            _write_sample_config(project_root / CONFIG_FILENAMES[0])
            return 0
        config = _load_config(project_root, args.config, no_config=args.no_config)
        if args.list_rules:
            rules = [rule for rule in _all_rules(config) if rule.id not in set(args.disable_rule)]
            print(render_rules(rules, "json" if args.format == "json" else "text"))
            return 0
        max_file_size = args.max_file_size if args.max_file_size is not None else config.max_file_size
        changed_paths = _load_changed_paths(args)
        report = scan_project(
            args.path,
            include_tests=args.include_tests,
            max_file_size=max_file_size,
            config_path=args.config,
            no_config=args.no_config,
            disabled_rules=args.disable_rule,
            exclude=args.exclude,
            baseline=args.baseline,
            changed_paths=changed_paths,
        )
        if args.write_baseline:
            _safe_write_path(args.write_baseline, project_root, "baseline")
            write_baseline(report, args.write_baseline)
        output = render_report(report, args.format, limit=args.limit, color=_use_color(args.color))
        if args.output:
            _safe_write_path(args.output, project_root, "output")
            Path(args.output).expanduser().write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        if args.github_annotations:
            annotations = render_github_annotations(report, limit=args.limit)
            if annotations:
                print(annotations)
        fail_on = args.fail_on if args.fail_on is not None else config.fail_on
        return 1 if should_fail(report, fail_on) else 0
    except Exception as exc:
        print(f"audit_code.py: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

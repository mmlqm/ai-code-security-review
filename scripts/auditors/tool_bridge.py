#!/usr/bin/env python3
"""
External security tool bridge — optional integration layer for deep scanning.

Runs industry-standard tools when available, parses their output into the
unified AuditFinding schema, and merges with scanner results.

Design principle: every tool is OPTIONAL. If not installed, skip gracefully.
No tool dependency is ever required.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ToolResult:
    """Output from one external tool run."""
    tool: str
    success: bool
    available: bool
    findings: list[dict] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""


# ── Tool registry ────────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, dict] = {
    "semgrep": {
        "binary": "semgrep",
        "install_hint": "pip install semgrep  or  brew install semgrep",
        "description": "Multi-language static analysis with 2000+ community rules",
        "category": "sast",
    },
    "gitleaks": {
        "binary": "gitleaks",
        "install_hint": "brew install gitleaks  or  go install github.com/gitleaks/gitleaks/v8@latest",
        "description": "Detect hardcoded secrets and credentials in git repos",
        "category": "secrets",
    },
    "hadolint": {
        "binary": "hadolint",
        "install_hint": "brew install hadolint  or  docker pull hadolint/hadolint",
        "description": "Dockerfile best-practice linter",
        "category": "docker",
    },
    "shellcheck": {
        "binary": "shellcheck",
        "install_hint": "apt install shellcheck  or  brew install shellcheck",
        "description": "Shell script static analysis",
        "category": "shell",
    },
    "checkov": {
        "binary": "checkov",
        "install_hint": "pip install checkov",
        "description": "Infrastructure-as-Code security scanning (Terraform, K8s, CloudFormation)",
        "category": "iac",
    },
    "bandit": {
        "binary": "bandit",
        "install_hint": "pip install bandit",
        "description": "Python security-focused static analysis",
        "category": "sast",
    },
    "npm_audit": {
        "binary": "npm",
        "install_hint": "Install Node.js: https://nodejs.org",
        "description": "Node.js dependency vulnerability scanner",
        "category": "supply-chain",
    },
    "trivy": {
        "binary": "trivy",
        "install_hint": "brew install trivy  or  see https://aquasecurity.github.io/trivy/latest/getting-started/installation/",  # audit-code: ignore docker-curl-pipe-shell
        "description": "Container, filesystem, and git repository vulnerability scanner",
        "category": "supply-chain",
    },
}


def _find_binary(name: str) -> str | None:
    """Locate a binary in PATH. Returns path or None."""
    return shutil.which(name)


def _run_command(cmd: list[str], *, timeout: int = 120, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a command safely with timeout."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, stdout="", stderr="Timed out")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, -2, stdout="", stderr="Binary not found")
    except Exception as exc:
        return subprocess.CompletedProcess(cmd, -3, stdout="", stderr=str(exc))


def check_availability() -> dict[str, bool]:
    """Check which tools are available in the current environment."""
    return {
        name: _find_binary(info["binary"]) is not None
        for name, info in TOOL_REGISTRY.items()
    }


def run_semgrep(target: Path, **kwargs) -> ToolResult:
    """Run Semgrep and parse findings."""
    binary = _find_binary("semgrep")
    if not binary:
        return ToolResult("semgrep", False, False, error="semgrep not installed")

    cmd = [
        binary, "scan",
        "--config", "auto",
        "--json",
        "--quiet",
        "--no-git-ignore",
        str(target),
    ]
    # Skip if there's a .semgrepignore or user prefs
    result = _run_command(cmd, timeout=kwargs.get("timeout", 180), cwd=target if target.is_dir() else target.parent)
    if result.returncode not in (0, 1):  # 0=clean, 1=findings
        return ToolResult("semgrep", False, True, error=result.stderr[:500])

    findings = []
    try:
        data = json.loads(result.stdout)
        for res in data.get("results", []):
            findings.append({
                "rule_id": f"semgrep-{res.get('check_id', 'unknown')}",
                "title": res.get("extra", {}).get("message", "Semgrep finding"),
                "severity": _map_semgrep_severity(res.get("extra", {}).get("severity", "WARNING")),
                "path": res.get("path", ""),
                "line": res.get("start", {}).get("line", 1),
                "column": res.get("start", {}).get("col", 1),
                "snippet": res.get("extra", {}).get("lines", ""),
                "remediation": res.get("extra", {}).get("fix", ""),
                "source": "semgrep",
            })
    except json.JSONDecodeError:
        return ToolResult("semgrep", False, True, error="Failed to parse Semgrep JSON output")

    return ToolResult("semgrep", True, True, findings=findings)


def run_gitleaks(target: Path, **kwargs) -> ToolResult:
    """Run Gitleaks and parse findings."""
    binary = _find_binary("gitleaks")
    if not binary:
        return ToolResult("gitleaks", False, False, error="gitleaks not installed")

    cmd = [
        binary, "detect",
        "--source", str(target),
        "--format", "json",
        "--no-git",
        "--verbose",
    ]
    result = _run_command(cmd, timeout=kwargs.get("timeout", 120))
    if result.returncode not in (0, 1):
        return ToolResult("gitleaks", False, True, error=result.stderr[:500])

    findings = []
    try:
        data = json.loads(result.stdout) if result.stdout else []
        for leak in data if isinstance(data, list) else []:
            findings.append({
                "rule_id": f"gitleaks-{leak.get('ruleID', 'unknown')}",
                "title": f"Hardcoded secret: {leak.get('Description', 'Unknown secret')}",
                "severity": "HIGH",
                "path": leak.get("File", ""),
                "line": leak.get("StartLine", 1),
                "column": leak.get("StartColumn", 1),
                "snippet": f"[REDACTED - {leak.get('ruleID', 'secret')}]",
                "remediation": "Remove from source, rotate the credential, use a secret manager.",
                "source": "gitleaks",
            })
    except (json.JSONDecodeError, AttributeError):
        pass

    return ToolResult("gitleaks", True, True, findings=findings)


def run_hadolint(target: Path, **kwargs) -> ToolResult:
    """Run Hadolint on all Dockerfiles in the target."""
    binary = _find_binary("hadolint")
    if not binary:
        return ToolResult("hadolint", False, False, error="hadolint not installed")

    findings = []
    dockerfiles = list(target.rglob("Dockerfile*")) if target.is_dir() else (
        [target] if "dockerfile" in target.name.lower() else []
    )

    for dockerfile in dockerfiles:
        if "node_modules" in dockerfile.parts:
            continue
        cmd = [binary, "--format", "json", str(dockerfile)]
        result = _run_command(cmd, timeout=kwargs.get("timeout", 30))
        if result.returncode not in (0, 1):
            continue
        try:
            data = json.loads(result.stdout) if result.stdout else []
            for issue in data if isinstance(data, list) else []:
                findings.append({
                    "rule_id": f"hadolint-{issue.get('code', 'unknown')}",
                    "title": issue.get("message", "Dockerfile issue"),
                    "severity": _map_hadolint_severity(issue.get("level", "warning")),
                    "path": str(dockerfile.relative_to(target) if target.is_dir() else dockerfile.name),
                    "line": issue.get("line", 1),
                    "column": issue.get("column", 1),
                    "snippet": issue.get("message", ""),
                    "remediation": "Fix the Dockerfile issue as recommended.",
                    "source": "hadolint",
                })
        except (json.JSONDecodeError, AttributeError):
            continue

    return ToolResult("hadolint", True, True, findings=findings)


def run_bandit(target: Path, **kwargs) -> ToolResult:
    """Run Bandit on Python files."""
    binary = _find_binary("bandit")
    if not binary:
        return ToolResult("bandit", False, False, error="bandit not installed")

    cmd = [binary, "-r", str(target), "-f", "json", "-q"]
    result = _run_command(cmd, timeout=kwargs.get("timeout", 120))
    if result.returncode not in (0, 1):
        return ToolResult("bandit", False, True, error=result.stderr[:500])

    findings = []
    try:
        data = json.loads(result.stdout)
        for res in data.get("results", []):
            findings.append({
                "rule_id": f"bandit-{res.get('test_id', 'unknown')}",
                "title": res.get("issue_text", "Bandit finding"),
                "severity": _map_bandit_severity(res.get("issue_severity", "low")),
                "path": res.get("filename", ""),
                "line": res.get("line_number", 1),
                "column": res.get("col_offset", 1) if res.get("col_offset") else 1,
                "snippet": res.get("code", "").strip() if res.get("code") else "",
                "remediation": res.get("more_info", ""),
                "source": "bandit",
            })
    except json.JSONDecodeError:
        pass

    return ToolResult("bandit", True, True, findings=findings)


def run_all(target: Path, *, tools: list[str] | None = None, timeout: int = 600) -> dict[str, ToolResult]:
    """
    Run all available external tools against a target.
    Returns a dict of tool_name → ToolResult.

    Tools are run sequentially to avoid resource contention.
    Each tool gets a sub-timeout; the total is capped by `timeout`.
    """
    available = check_availability()
    per_tool_timeout = max(30, timeout // max(len(available), 1))

    runners = {
        "semgrep": run_semgrep,
        "gitleaks": run_gitleaks,
        "hadolint": run_hadolint,
        "bandit": run_bandit,
    }

    results = {}
    for name, runner in runners.items():
        if tools and name not in tools:
            continue
        if not available.get(name):
            results[name] = ToolResult(name, False, False, error=f"{name} not installed — {TOOL_REGISTRY[name]['install_hint']}")
            continue
        results[name] = runner(target, timeout=per_tool_timeout)

    return results


def merge_external_findings(
    scanner_report: Any,     # AuditReport from audit_code
    external_results: dict[str, ToolResult],
) -> dict:
    """Merge scanner findings with external tool findings into a unified result."""
    all_findings = [f.to_dict() for f in scanner_report.findings]

    for tool_name, result in external_results.items():
        if result.success and result.findings:
            all_findings.extend(result.findings)

    # Simple dedup by (rule_id, path, line)
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get("rule_id", ""), f.get("path", ""), f.get("line", 0))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return {
        "scanner": scanner_report.summary.to_dict(),
        "external_tools": {
            name: {
                "available": r.available,
                "success": r.success,
                "finding_count": len(r.findings),
                "error": r.error if not r.success else None,
            }
            for name, r in external_results.items()
        },
        "findings": deduped,
        "total_findings": len(deduped),
    }


# ── Severity mappers ─────────────────────────────────────────────────

def _map_semgrep_severity(sev: str) -> str:
    mapping = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "INVENTORY": "INFO"}
    return mapping.get(sev.upper(), "MEDIUM")


def _map_hadolint_severity(level: str) -> str:
    mapping = {"error": "HIGH", "warning": "MEDIUM", "info": "LOW", "style": "INFO"}
    return mapping.get(level.lower(), "MEDIUM")


def _map_bandit_severity(sev: str) -> str:
    mapping = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return mapping.get(sev.upper(), "LOW")

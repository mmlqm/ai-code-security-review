#!/usr/bin/env python3
"""
Build an AI-assisted security review pack for Claude, Codex, or a generic LLM.

The pack is generated locally from the deterministic scanner output. It does
not call any model or network service. Use it to hand Claude/Codex a compact
review brief: scan summary, redacted findings, security-sensitive files, and a
platform-specific prompt for deep review.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

import audit_code


SECURITY_FILENAMES = {
    ".env",
    ".env.example",
    ".github/workflows/validate.yml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "cargo.toml",
}

SECURITY_PATH_PARTS = {
    ".github/workflows",
    "auth",
    "authentication",
    "authorization",
    "billing",
    "checkout",
    "config",
    "deploy",
    "docker",
    "iam",
    "infra",
    "k8s",
    "kubernetes",
    "login",
    "middleware",
    "payment",
    "permission",
    "policy",
    "rbac",
    "secret",
    "security",
    "session",
    "token",
}


def _read_changed_paths(path: str | None, inline_paths: Iterable[str]) -> list[str]:
    changed = [item.strip() for item in inline_paths if item and item.strip()]
    if path:
        changed.extend(
            item.strip()
            for item in Path(path).expanduser().read_text(encoding="utf-8").splitlines()
            if item and item.strip()
        )
    return changed


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_ignored_dir(name: str) -> bool:
    return name in audit_code.DEFAULT_IGNORED_DIRS or name.startswith(".mypy_cache")


def collect_hotspots(root: Path, limit: int) -> list[str]:
    """Return security-relevant files the AI should inspect first."""
    project_root = root.parent if root.is_file() else root
    if root.is_file():
        return [_rel(root, project_root)]

    hotspots: list[str] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [name for name in dirnames if not _is_ignored_dir(name)]
        current = Path(dirpath)
        for filename in filenames:
            path = current / filename
            rel = _rel(path, project_root)
            rel_lower = rel.lower()
            path_parts = {part.lower() for part in Path(rel_lower).parts}
            is_special = rel_lower in SECURITY_FILENAMES or filename.lower() in SECURITY_FILENAMES
            is_hot_path = bool(audit_code.SENSITIVE_PATH_RE.search(rel_lower))
            is_named_area = bool(path_parts & SECURITY_PATH_PARTS) or ".github/workflows" in rel_lower
            if is_special or is_hot_path or is_named_area:
                hotspots.append(rel)
        if len(hotspots) >= limit:
            break
    return sorted(dict.fromkeys(hotspots))[:limit]


def _agent_prompt(agent: str, depth: str) -> str:
    shared = (
        "Run the offline scanner first, treat findings as leads rather than final "
        "verdicts, then perform AI-assisted code review. Redact secrets. Lead with "
        "release blockers, then review-required items, hardening, and coverage."
    )
    deep = (
        "Use the seven dimensions in references/deep-analysis.md: auth, dataflow, "
        "crypto, info leak, business logic, supply chain, and architecture. For "
        "each HIGH or CRITICAL claim, try to disprove it before reporting it."
    )
    fast = "Focus on scanner findings, likely false positives, and concrete patches."
    detail = deep if depth == "deep" else fast
    if agent == "codex":
        return (
            "Use $ai-code-security-review on this repository. "
            f"{shared} {detail}"
        )
    if agent == "claude":
        return (
            "Use the ai-code-security-review skill as a defensive application "
            f"security reviewer. {shared} {detail}"
        )
    return f"Act as a defensive application security reviewer. {shared} {detail}"


def _format_findings(report: audit_code.AuditReport, limit: int) -> str:
    payload = {
        "summary": report.summary.to_dict(),
        "findings": [finding.to_dict() for finding in report.findings[:limit]],
    }
    if len(report.findings) > limit:
        payload["truncated_findings"] = len(report.findings) - limit
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_pack(
    root: str | os.PathLike[str],
    *,
    agent: str = "codex",
    depth: str = "deep",
    include_tests: bool = False,
    max_file_size: int = 512 * 1024,
    config_path: str | None = None,
    no_config: bool = False,
    disabled_rules: Iterable[str] = (),
    exclude: Iterable[str] = (),
    baseline: str | None = None,
    changed_paths: Iterable[str] = (),
    finding_limit: int = 80,
    hotspot_limit: int = 80,
) -> str:
    root_path = Path(root).expanduser().resolve()
    report = audit_code.scan_project(
        root_path,
        include_tests=include_tests,
        max_file_size=max_file_size,
        config_path=config_path,
        no_config=no_config,
        disabled_rules=disabled_rules,
        exclude=exclude,
        baseline=baseline,
        changed_paths=changed_paths,
    )
    hotspots = collect_hotspots(root_path, hotspot_limit)
    changed = [item for item in changed_paths if item]
    prompt = _agent_prompt(agent, depth)
    config_hint = config_path or ".audit-code.toml"

    lines = [
        "# AI-Assisted Code Security Review Pack",
        "",
        f"- Agent: {agent}",
        f"- Depth: {depth}",
        f"- Root: `{root_path}`",
        f"- Scanner status: {report.summary.status.upper()}",
        f"- Score: {report.summary.score}/100",
        f"- Findings: {report.summary.findings_total}",
        f"- Config: `{config_hint}`",
        "",
        "## How To Use",
        "",
        "1. Paste this pack into Claude, Codex, or another review agent.",
        "2. Ask the agent to verify the scanner findings against source code.",
        "3. Ask for release blockers first, then review-required items and hardening.",
        "4. For serious findings, require a concrete fix and regression test.",
        "",
        "## Agent Prompt",
        "",
        "```text",
        prompt,
        "```",
        "",
        "## Scanner Output",
        "",
        "```json",
        _format_findings(report, finding_limit),
        "```",
        "",
        "## Review Hotspots",
        "",
    ]
    if hotspots:
        lines.extend(f"- `{path}`" for path in hotspots)
    else:
        lines.append("- No security-sensitive file names were detected by the hotspot heuristic.")
    if changed:
        lines.extend(["", "## Changed Files", ""])
        lines.extend(f"- `{path}`" for path in changed)
    lines.extend(
        [
            "",
            "## Suggested Review Order",
            "",
            "1. Confirm CRITICAL and HIGH scanner findings against source code.",
            "2. Inspect auth, session, token, permission, and tenant-boundary code.",
            "3. Trace external input to SQL, shell, template, file, HTTP, and deserialization sinks.",
            "4. Review secrets, crypto, TLS, CORS, cookies, Docker/K8s, CI, and dependency files.",
            "5. Check business logic for workflow skips, replay, race conditions, and idempotency gaps.",
            "6. Report what was reviewed and what remains out of scope.",
            "",
            "## Configuration Notes",
            "",
            "- Use `.audit-code.toml` for team rules, disabled rules, baseline paths, and excludes.",
            "- Use `.auditignore` for generated, vendored, or release-output paths.",
            "- Use `--changed-files-from changed.txt` for PR/MR review packs.",
            "- Keep AI review defensive and code-focused; do not run live target probes from this pack.",
            "",
        ]
    )
    return "\n".join(lines)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an offline Claude/Codex review pack from scanner output."
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository, directory, or file to review.")
    parser.add_argument("--agent", choices=("codex", "claude", "generic"), default="codex")
    parser.add_argument("--depth", choices=("fast", "deep"), default="deep")
    parser.add_argument("--output", default="ai-code-review-pack.md", help="Markdown output path.")
    parser.add_argument("--include-tests", action="store_true", help="Include tests and fixtures.")
    parser.add_argument("--max-file-size", type=int, default=512 * 1024)
    parser.add_argument("--config", help="Path to .audit-code.toml.")
    parser.add_argument("--no-config", action="store_true")
    parser.add_argument("--disable-rule", action="append", default=[])
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--baseline")
    parser.add_argument("--changed-files", nargs="*", default=[])
    parser.add_argument("--changed-files-from")
    parser.add_argument("--finding-limit", type=int, default=80)
    parser.add_argument("--hotspot-limit", type=int, default=80)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        changed_paths = _read_changed_paths(args.changed_files_from, args.changed_files)
        pack = build_pack(
            args.path,
            agent=args.agent,
            depth=args.depth,
            include_tests=args.include_tests,
            max_file_size=args.max_file_size,
            config_path=args.config,
            no_config=args.no_config,
            disabled_rules=args.disable_rule,
            exclude=args.exclude,
            baseline=args.baseline,
            changed_paths=changed_paths,
            finding_limit=args.finding_limit,
            hotspot_limit=args.hotspot_limit,
        )
        output = Path(args.output).expanduser()
        output.write_text(pack + "\n", encoding="utf-8")
        print(f"Wrote AI review pack: {output}")
        return 0
    except Exception as exc:
        print(f"ai_review_pack.py: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

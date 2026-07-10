#!/usr/bin/env python3
"""
Merge scanner output and Claude/Codex findings into a final review report.

This script is deterministic and offline. It does not call an AI provider or
GitHub API. Feed it JSON produced by an AI reviewer, or run it without AI input
to produce a scanner-only release report.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable

import audit_code


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}


def _severity(value: Any) -> str:
    normalized = str(value or "INFO").upper()
    return normalized if normalized in SEVERITY_RANK else "INFO"


def _confidence(value: Any) -> str:
    normalized = str(value or "medium").lower()
    return normalized if normalized in {"high", "medium", "low"} else "medium"


def _parse_location(raw: dict[str, Any]) -> tuple[str, int]:
    if raw.get("path") or raw.get("file"):
        path = str(raw.get("path") or raw.get("file"))
        return path, _safe_int(raw.get("line"), 1)
    location = str(raw.get("location") or ".")
    match = re.match(r"^(?P<path>.*?):(?P<line>\d+)(?::\d+)?$", location)
    if match:
        return match.group("path") or ".", _safe_int(match.group("line"), 1)
    return location, 1


def _safe_int(value: Any, default: int) -> int:
    try:
        return max(int(value), 1)
    except (TypeError, ValueError):
        return default


def _redact(value: Any) -> str:
    return audit_code._redact(str(value or "").strip())


def _fingerprint(item: dict[str, Any]) -> str:
    key = "|".join(
        [
            str(item.get("source", "")),
            str(item.get("rule_id", "")),
            str(item.get("title", "")),
            str(item.get("path", "")),
            str(item.get("line", "")),
        ]
    )
    import hashlib

    return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:20]


def _scanner_items(scanner_report: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for finding in scanner_report.get("findings", []):
        item = {
            "source": "scanner",
            "dimension": finding.get("category", "scanner"),
            "rule_id": finding.get("rule_id", ""),
            "title": finding.get("title", "Scanner finding"),
            "severity": _severity(finding.get("severity")),
            "confidence": _confidence(finding.get("confidence")),
            "path": finding.get("path", "."),
            "line": _safe_int(finding.get("line"), 1),
            "description": finding.get("snippet", ""),
            "risk_path": "",
            "impact": "",
            "remediation": finding.get("remediation", ""),
            "test_recommendation": "",
            "cwe": finding.get("cwe", ""),
            "linked_findings": [],
        }
        item["fingerprint"] = finding.get("fingerprint") or _fingerprint(item)
        items.append(item)
    return items


def _ai_items(payload: dict[str, Any], source_name: str) -> list[dict[str, Any]]:
    raw_findings = []
    for key in ("findings", "results", "issues"):
        value = payload.get(key)
        if isinstance(value, list):
            raw_findings.extend(value)
    chains = payload.get("chains")
    if isinstance(chains, list):
        raw_findings.extend({**chain, "dimension": "chain-synthesis", "is_chain": True} for chain in chains)

    items: list[dict[str, Any]] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        path, line = _parse_location(raw)
        item = {
            "source": source_name,
            "dimension": str(raw.get("dimension") or "ai"),
            "rule_id": str(raw.get("rule_id") or raw.get("id") or ""),
            "title": str(raw.get("title") or raw.get("summary") or "AI finding"),
            "severity": _severity(raw.get("severity")),
            "confidence": _confidence(raw.get("confidence")),
            "path": path,
            "line": line,
            "description": raw.get("description") or raw.get("details") or "",
            "risk_path": raw.get("risk_path") or raw.get("evidence_path") or raw.get("attack_scenario") or raw.get("scenario") or "",
            "impact": raw.get("impact") or "",
            "remediation": raw.get("remediation") or raw.get("fix") or "",
            "test_recommendation": raw.get("test_recommendation") or raw.get("test") or "",
            "cwe": raw.get("cwe") or "",
            "linked_findings": raw.get("linked_findings") or [],
        }
        item["fingerprint"] = str(raw.get("fingerprint") or _fingerprint(item))
        items.append(item)
    return items


def _load_json(path: str | os.PathLike[str]) -> dict[str, Any]:
    return json.loads(Path(path).expanduser().read_text(encoding="utf-8"))


def _load_scanner_report(
    root: str | os.PathLike[str],
    scanner_report_path: str | None,
    include_tests: bool,
    config_path: str | None,
    no_config: bool,
    baseline: str | None,
) -> dict[str, Any]:
    if scanner_report_path:
        return _load_json(scanner_report_path)
    report = audit_code.scan_project(
        root,
        include_tests=include_tests,
        config_path=config_path,
        no_config=no_config,
        baseline=baseline,
    )
    return report.to_dict()


def _dedupe(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for item in items:
        key = item.get("fingerprint") or _fingerprint(item)
        existing = by_key.get(key)
        if not existing:
            by_key[key] = item
            continue
        if SEVERITY_RANK[item["severity"]] < SEVERITY_RANK[existing["severity"]]:
            by_key[key] = item
    return sorted(
        by_key.values(),
        key=lambda item: (
            SEVERITY_RANK[item["severity"]],
            item.get("path", ""),
            item.get("line", 1),
            item.get("title", ""),
        ),
    )


def _counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for item in items:
        counts[item["severity"]] += 1
    return counts


def _section_title(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "Release Blockers"
    if severity == "MEDIUM":
        return "Requires Review"
    return "Hardening"


def _render_item(item: dict[str, Any]) -> list[str]:
    location = f"{item.get('path', '.')}:{item.get('line', 1)}"
    lines = [
        f"### [{item['severity']}] {item['title']}",
        "",
        f"- Source: `{item.get('source', 'unknown')}` / `{item.get('dimension', 'unknown')}`",
        f"- Location: `{location}`",
        f"- Confidence: `{item.get('confidence', 'medium')}`",
    ]
    if item.get("rule_id"):
        lines.append(f"- Rule ID: `{item['rule_id']}`")
    if item.get("cwe"):
        lines.append(f"- CWE: `{item['cwe']}`")
    if item.get("linked_findings"):
        linked = ", ".join(f"`{value}`" for value in item["linked_findings"])
        lines.append(f"- Linked findings: {linked}")
    detail_fields = [
        ("Description", item.get("description")),
        ("Risk path", item.get("risk_path")),
        ("Impact", item.get("impact")),
        ("Remediation", item.get("remediation")),
        ("Test to add", item.get("test_recommendation")),
    ]
    for label, value in detail_fields:
        text = _redact(value)
        if text:
            lines.extend(["", f"**{label}:** {text}"])
    lines.append("")
    return lines


def render_markdown(scanner_report: dict[str, Any], items: list[dict[str, Any]]) -> str:
    counts = _counts(items)
    summary = scanner_report.get("summary", {})
    lines = [
        "# AI Code Security Review Report",
        "",
        "## Summary",
        "",
        f"- Generated at: `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`",
        f"- Target: `{summary.get('root', '.')}`",
        f"- Scanner status: `{str(summary.get('status', 'unknown')).upper()}`",
        f"- Scanner score: `{summary.get('score', 'n/a')}`",
        f"- Combined findings: {len(items)}",
        f"- Counts: CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}, INFO={counts['INFO']}",
        "",
    ]
    for heading, severities in (
        ("Release Blockers", ("CRITICAL", "HIGH")),
        ("Requires Review", ("MEDIUM",)),
        ("Hardening", ("LOW", "INFO")),
    ):
        section_items = [item for item in items if item["severity"] in severities]
        lines.extend([f"## {heading}", ""])
        if not section_items:
            lines.extend(["No findings in this section.", ""])
            continue
        for item in section_items:
            lines.extend(_render_item(item))
    lines.extend(
        [
            "## Coverage Statement",
            "",
            "This report merges deterministic scanner output with any provided Claude/Codex JSON findings. AI findings should be verified against source before release decisions.",
            "",
        ]
    )
    return "\n".join(lines)


def render_pr_comment(scanner_report: dict[str, Any], items: list[dict[str, Any]], limit: int = 10) -> str:
    counts = _counts(items)
    blockers = [item for item in items if item["severity"] in {"CRITICAL", "HIGH"}]
    lines = [
        "## AI Code Security Review",
        "",
        f"Scanner status: `{str(scanner_report.get('summary', {}).get('status', 'unknown')).upper()}`",
        f"Combined findings: **{len(items)}** (CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}, INFO={counts['INFO']})",
        "",
    ]
    if blockers:
        lines.extend(["### Release Blockers", ""])
        for item in blockers[:limit]:
            lines.append(f"- **[{item['severity']}] {item['title']}** at `{item.get('path', '.')}:{item.get('line', 1)}`")
        if len(blockers) > limit:
            lines.append(f"- ...and {len(blockers) - limit} more blockers.")
    else:
        lines.append("No CRITICAL or HIGH findings in the combined report.")
    lines.extend(["", "See the full generated Markdown report artifact for details.", ""])
    return "\n".join(lines)


def build_report(
    root: str | os.PathLike[str],
    *,
    scanner_report_path: str | None = None,
    ai_finding_paths: Iterable[str] = (),
    include_tests: bool = False,
    config_path: str | None = None,
    no_config: bool = False,
    baseline: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    scanner_report = _load_scanner_report(
        root,
        scanner_report_path,
        include_tests=include_tests,
        config_path=config_path,
        no_config=no_config,
        baseline=baseline,
    )
    items = _scanner_items(scanner_report)
    for path in ai_finding_paths:
        payload = _load_json(path)
        items.extend(_ai_items(payload, Path(path).name))
    return scanner_report, _dedupe(items)


def should_fail(items: list[dict[str, Any]], fail_on: str) -> bool:
    threshold = str(fail_on or "none").upper()
    if threshold == "NONE":
        return False
    if threshold not in SEVERITY_RANK:
        threshold = "HIGH"
    return any(SEVERITY_RANK[item["severity"]] <= SEVERITY_RANK[threshold] for item in items)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge scanner and Claude/Codex JSON findings into a final security report."
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository root. Used when --scanner-report is omitted.")
    parser.add_argument("--scanner-report", help="Existing audit_code.py JSON report.")
    parser.add_argument("--ai-findings", action="append", default=[], help="Claude/Codex JSON findings file. Can be repeated.")
    parser.add_argument("--output", default="ai-code-security-report.md", help="Markdown report output path.")
    parser.add_argument("--pr-comment-output", help="Optional compact PR comment Markdown output path.")
    parser.add_argument("--json-output", help="Optional normalized combined JSON output path.")
    parser.add_argument("--include-tests", action="store_true")
    parser.add_argument("--config", help="Path to .audit-code.toml.")
    parser.add_argument("--no-config", action="store_true")
    parser.add_argument("--baseline")
    parser.add_argument("--fail-on", default="none", help="Fail when combined findings meet this severity, or none.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        scanner_report, items = build_report(
            args.path,
            scanner_report_path=args.scanner_report,
            ai_finding_paths=args.ai_findings,
            include_tests=args.include_tests,
            config_path=args.config,
            no_config=args.no_config,
            baseline=args.baseline,
        )
        Path(args.output).expanduser().write_text(render_markdown(scanner_report, items) + "\n", encoding="utf-8")
        if args.pr_comment_output:
            Path(args.pr_comment_output).expanduser().write_text(
                render_pr_comment(scanner_report, items) + "\n",
                encoding="utf-8",
            )
        if args.json_output:
            payload = {"summary": {"combined_findings": len(items), "counts": _counts(items)}, "findings": items}
            Path(args.json_output).expanduser().write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        print(f"Wrote AI security report: {args.output}")
        return 1 if should_fail(items, args.fail_on) else 0
    except Exception as exc:
        print(f"ai_report.py: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Variable-based taint tracking for same-file data flow detection.

Catches patterns the regex scanner misses:
    sql = f"SELECT * FROM users WHERE id = {user_input}"   # line 5
    cursor.execute(sql)                                      # line 20 ← missed by regex

Design: lightweight, same-file only, operates on string-level patterns.
Not a full CFG — just catches the most common "assign then use" pattern.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple


class TrackRule(NamedTuple):
    """A variable tracking rule: detect dangerous values assigned to variables,
    then flag when those variables reach dangerous sinks."""
    rule_id: str
    title: str
    severity: str
    assign_pattern: str           # regex with capture group for variable name
    sink_pattern: str             # regex with {var} placeholder for the variable
    remediation: str
    cwe: str = ""
    extensions: tuple[str, ...] = ()


# ── Built-in tracking rules ─────────────────────────────────────────
TRACK_RULES: list[TrackRule] = [
    # SQL injection via variable
    TrackRule(
        "track-sql-fstring",
        "SQL query assigned to variable then executed",
        "HIGH",
        # Capture: var_name = f"SELECT...{input}" or var_name = "SELECT..." + input
        r"(?P<var>\w+)\s*=\s*(?:f[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b|"
        r"[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\+)",
        r"\.execute\s*\(\s*{var}\b",
        "Use parameterized queries. Never build SQL from interpolated strings assigned to variables.",
        cwe="CWE-89",
        extensions=(".py",),
    ),
    TrackRule(
        "track-sql-concat",
        "SQL string concatenation stored in variable then executed",
        "HIGH",
        r"(?P<var>\w+)\s*=\s*.+\+\s*.+\b(?:SELECT|INSERT|UPDATE|DELETE)\b",
        r"\.execute\s*\(\s*{var}\b",
        "Use parameterized queries instead of string concatenation for SQL.",
        cwe="CWE-89",
    ),
    # Shell command via variable
    TrackRule(
        "track-shell-command",
        "Shell command built in variable then executed",
        "HIGH",
        r"(?P<var>\w+)\s*=\s*(?:f[\"'].*(?:rm\s|curl\s|wget\s|sudo\s|chmod\s)|[\"'].*(?:rm\s|curl\s|wget\s).*[\"']\s*\+)",
        r"(?:subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(\s*{var}|os\.system\s*\(\s*{var}|os\.popen\s*\(\s*{var})",
        "Use subprocess with an argument list, not a shell string built from variables.",
        cwe="CWE-78",
        extensions=(".py",),
    ),
    TrackRule(
        "track-shell-js",
        "Shell command built in variable then exec'd (JS)",
        "HIGH",
        r"(?:const|let|var)\s+(?P<var>\w+)\s*=\s*`[^`]*(?:rm\s|curl\s|wget\s)",
        r"(?:exec|execSync)\s*\(\s*{var}\b",
        "Use execFile/spawn with argument arrays instead of building shell commands in template strings.",
        cwe="CWE-78",
        extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    ),
    # Path traversal via variable
    TrackRule(
        "track-path-traversal",
        "File path built from request input in variable then opened",
        "HIGH",
        r"(?P<var>\w+)\s*=\s*(?:os\.path\.join|pathlib\.Path|path\.join)\s*\([^)]*(?:request\.|req\.|args\.get|form\.get|params\[)",
        r"(?:open|send_file|read|write)\s*\(\s*{var}\b",
        "Normalize and allowlist file paths. Never join user input into file paths.",
        cwe="CWE-22",
    ),
    # Eval via variable
    TrackRule(
        "track-eval",
        "Code string built in variable then eval'd",
        "CRITICAL",
        r"(?P<var>\w+)\s*=\s*.+\+\s*.+\s*\+\s*",
        r"(?:eval|exec|Function)\s*\(\s*{var}\b",
        "Never build code strings for eval/exec/Function. Use a purpose-built parser or sandbox.",
        cwe="CWE-94",
    ),
    # Template injection via variable
    TrackRule(
        "track-ssti",
        "Template string built from request input then rendered",
        "HIGH",
        r"(?P<var>\w+)\s*=\s*(?:request\.(?:args|form|json|data)|req\.(?:query|body|params))",
        r"render_template_string\s*\(\s*{var}\b",
        "Render fixed templates only. Pass user input as escaped template variables.",
        cwe="CWE-1336",
        extensions=(".py",),
    ),
    # SSRF via variable
    TrackRule(
        "track-ssrf",
        "URL built from request input in variable then fetched",
        "HIGH",
        r"(?P<var>\w+)\s*=\s*(?:request\.(?:args|form|json|data)|req\.(?:query|body|params)|params\[)",
        r"(?:requests\.(?:get|post|put|delete|head|patch|request)|fetch|axios|http\.Get)\s*\(\s*{var}\b",
        "Validate outbound URLs against a scheme and host allowlist. Block internal network ranges.",
        cwe="CWE-918",
    ),
]


def scan_file_for_tracked_variables(
    path: Path,
    text: str,
    rules: list[TrackRule],
) -> list[dict]:
    """
    Scan a file for variable-based taint flows.
    Returns list of findings with source and sink locations.
    """
    lines = text.splitlines()
    findings = []

    for rule in rules:
        # Check extension filter
        if rule.extensions:
            ext = path.suffix.lower()
            if ext not in rule.extensions:
                continue

        assign_re = re.compile(rule.assign_pattern, re.IGNORECASE)

        # Phase 1: find all variable assignments that look dangerous
        tainted_vars: dict[str, list[int]] = {}   # var_name → [line_numbers]
        for line_no, line in enumerate(lines, 1):
            for match in assign_re.finditer(line):
                var_name = match.group("var")
                if var_name:
                    tainted_vars.setdefault(var_name, []).append(line_no)

        if not tainted_vars:
            continue

        # Phase 2: check if any tainted variable reaches a dangerous sink
        for var_name, assign_lines in tainted_vars.items():
            # Escape the variable name for safe regex insertion
            escaped_var = re.escape(var_name)
            sink_pattern = rule.sink_pattern.replace("{var}", escaped_var)
            sink_re = re.compile(sink_pattern, re.IGNORECASE)

            for line_no, line in enumerate(lines, 1):
                if sink_re.search(line):
                    findings.append({
                        "rule_id": rule.rule_id,
                        "title": rule.title,
                        "severity": rule.severity,
                        "variable": var_name,
                        "assign_lines": assign_lines,
                        "sink_line": line_no,
                        "sink_snippet": line.strip()[:200],
                        "remediation": rule.remediation,
                        "cwe": rule.cwe,
                    })
                    # Only report each variable-sink pair once per file
                    break

    return findings

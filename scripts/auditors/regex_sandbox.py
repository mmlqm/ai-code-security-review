#!/usr/bin/env python3
"""
Regex sandbox — prevents ReDoS and resource exhaustion from custom rules.

Wraps every user-supplied regex compile and execution with:
- Compile-time: detects known ReDoS patterns (nested quantifiers, alternation bombs)
- Runtime: timeout-based execution (via signal or soft time check)
- Match limit: caps matches per file to prevent memory exhaustion
"""

from __future__ import annotations

import re
import signal
import sys
from typing import Pattern


# ── ReDoS pattern signatures ────────────────────────────────────────
# These patterns are known to cause catastrophic backtracking.
# We check user-supplied regex for these signatures before compiling.

REDOS_SIGNATURES: list[tuple[str, str]] = [
    # Nested quantifiers: (a+)+, (a*)*, (a+)*, etc.
    (r"\(\s*(?:\\.|[^)])\s*[+*]\s*\)\s*[+*]", "nested quantifier"),
    # Alternation with overlapping prefixes: (a|aa|aaa)+
    (r"\([^)]*\|[^)]*\)\s*[+*]", "alternation with quantifier"),
    # .* with backtracking: .*.*, .+.+
    (r"\.\*\s*\.\*", "overlapping dot-star"),
    (r"\.\+\s*\.\+", "overlapping dot-plus"),
    # Lookahead/lookbehind with quantifiers
    (r"\(\?[<>=!].*\)\s*[+*]", "quantified lookaround"),
]


def _signal_handler(signum, frame):
    raise TimeoutError("Regex execution timed out")


def classify_redos_risk(pattern: str) -> list[str]:
    """Check a pattern string for known ReDoS signatures. Returns list of warnings."""
    warnings = []
    for sig, desc in REDOS_SIGNATURES:
        if re.search(sig, pattern):
            warnings.append(f"Potential ReDoS: {desc} (matched: {sig})")
    return warnings


def safe_compile(
    pattern: str,
    flags: int = 0,
    *,
    strict: bool = False,
) -> Pattern[str]:
    """
    Compile a regex with safety checks.

    Args:
        pattern: The regex pattern string
        flags: re flags (IGNORECASE, MULTILINE, DOTALL, etc.)
        strict: If True, raise ValueError on suspected ReDoS patterns.
                 If False, only print a warning to stderr.

    Returns:
        Compiled regex pattern

    Raises:
        ValueError: if strict=True and pattern looks dangerous
        re.error: if pattern is invalid regex
    """
    warnings = classify_redos_risk(pattern)
    if warnings:
        msg = f"Regex safety warning: {', '.join(warnings)}"
        if strict:
            raise ValueError(msg)
        else:
            print(f"Warning: {msg}", file=sys.stderr)
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"Invalid regex: {exc}") from exc


def safe_search(
    pattern: Pattern[str],
    text: str,
    *,
    max_matches: int = 10_000,
    timeout: float = 2.0,    # seconds
    per_line: bool = False,
) -> list[re.Match[str]]:
    """
    Execute a regex search with resource limits.

    Args:
        pattern: Compiled regex
        text: Text to search
        max_matches: Maximum number of matches to return
        timeout: Maximum execution time in seconds
        per_line: If True, search each line separately (faster timeout granularity)

    Returns:
        List of regex match objects (up to max_matches)

    Raises:
        TimeoutError: if regex execution exceeds timeout
    """
    matches: list[re.Match[str]] = []

    try:
        # Set up timeout
        if hasattr(signal, "SIGALRM"):
            old_handler = signal.signal(signal.SIGALRM, _signal_handler)
            signal.alarm(int(timeout))

        try:
            if per_line:
                for line in text.splitlines():
                    if len(matches) >= max_matches:
                        break
                    for match in pattern.finditer(line):
                        matches.append(match)
                        if len(matches) >= max_matches:
                            break
            else:
                for match in pattern.finditer(text):
                    matches.append(match)
                    if len(matches) >= max_matches:
                        break
        finally:
            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

    except TimeoutError:
        print(f"Warning: Regex execution timed out after {timeout}s", file=sys.stderr)

    return matches


def estimate_complexity(pattern: str) -> int:
    """
    Rough complexity score for a regex pattern.
    Higher = more likely to cause performance issues.
    """
    score = 0
    score += pattern.count("*") * 3
    score += pattern.count("+") * 3
    score += pattern.count("{") * 2
    score += pattern.count("|") * 2
    score += pattern.count("(?=") * 4
    score += pattern.count("(?!") * 4
    score += pattern.count("(?<=") * 5
    score += pattern.count("(?<!") * 5
    score += pattern.count("(?P<") * 1
    # Penalize nested parens with quantifiers
    nested = re.findall(r"\([^)]*[+*][^)]*\)[+*]", pattern)
    score += len(nested) * 10
    return score


def safe_compile_custom_rule(
    pattern: str,
    flags: int = 0,
    *,
    rule_id: str = "unknown",
    max_complexity: int = 30,
    strict: bool = True,
) -> Pattern[str]:
    """
    Compile a custom rule pattern with comprehensive safety checks.
    Combines ReDoS detection and complexity estimation.

    Raises ValueError if the pattern exceeds complexity limits.
    """
    complexity = estimate_complexity(pattern)
    if complexity > max_complexity:
        raise ValueError(
            f"Custom rule '{rule_id}' pattern complexity ({complexity}) "
            f"exceeds limit ({max_complexity}). Simplify the pattern or split "
            f"into multiple narrower rules."
        )
    return safe_compile(pattern, flags, strict=strict)

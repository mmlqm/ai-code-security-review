#!/usr/bin/env python3
"""
Enhanced secret redaction engine — covers what the basic scanner misses.
Handles: GitHub PAT, GitLab tokens, JWT, Slack webhooks, Stripe keys,
Generic base64 high-entropy strings, and YAML unquoted assignments.

Pure stdlib, zero dependencies.
"""

from __future__ import annotations

import base64
import math
import re
import string


# ── Recognized token formats (prefix → label) ──────────────────────
TOKEN_PATTERNS: dict[str, str] = {
    # GitHub
    r"ghp_[A-Za-z0-9]{36}": "github-classic-pat",
    r"github_pat_[A-Za-z0-9_]{40,120}": "github-fine-grained-pat",
    r"gho_[A-Za-z0-9]{36}": "github-oauth-token",
    r"ghu_[A-Za-z0-9]{36}": "github-user-token",
    r"ghs_[A-Za-z0-9]{36}": "github-server-token",
    r"ghr_[A-Za-z0-9]{36}": "github-refresh-token",
    # GitLab
    r"glpat-[A-Za-z0-9_-]{20,64}": "gitlab-personal-access-token",
    r"gldt-[A-Za-z0-9_-]{20,64}": "gitlab-deploy-token",
    r"glft-[A-Za-z0-9_-]{20,64}": "gitlab-feed-token",
    r"glrt-[A-Za-z0-9_-]{20,64}": "gitlab-runner-token",
    r"glsoat-[A-Za-z0-9_-]{20,64}": "gitlab-service-account-token",
    # Slack
    r"xox[bpras]-[A-Za-z0-9-]{10,80}": "slack-token",
    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+": "slack-webhook",
    # Stripe
    r"sk_live_[A-Za-z0-9]{24,99}": "stripe-live-secret-key",
    r"pk_live_[A-Za-z0-9]{24,99}": "stripe-live-publishable-key",
    r"rk_live_[A-Za-z0-9]{24,99}": "stripe-live-restricted-key",
    # JWT tokens (3 base64url segments separated by dots)
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+": "jwt-token",
    # Generic API key patterns
    r"sk-[A-Za-z0-9]{32,128}": "openai-api-key",
    r"sk-ant-[A-Za-z0-9_-]{32,128}": "anthropic-api-key",
    # Heroku
    r"[A-Za-z0-9_-]{8}-[A-Za-z0-9_-]{8}-[A-Za-z0-9_-]{8}-[A-Za-z0-9_-]{8}": "heroku-api-key",
    # Generic high-entropy assignment
    r"(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|private[_-]?key|access[_-]?key)[\s:=]+[\"']?([A-Za-z0-9+/=]{32,})[\"']?": "generic-secret",
}

# ── YAML/TOML unquoted secret detection ───────────────────────────
YAML_SECRET_RE = re.compile(
    r"(?im)^(\s*)(?P<key>(?:api[_-]?key|secret|token|password|passwd|credential|"
    r"private[_-]?key|access[_-]?key|auth[_-]?token))[\s]*:[\s]*(?P<value>[^\s#\"'{]+)",
)

# ── Entropy thresholds ─────────────────────────────────────────────
ENTROPY_THRESHOLD = 4.2      # Shannon entropy floor for "random-looking"
MIN_TOKEN_LENGTH = 20        # Shorter than this → probably not a real token
MAX_TOKEN_LENGTH = 512       # Longer than this → probably encoded binary data

# Binary header signatures that high-entropy strings commonly match
BINARY_SIGNATURES = [
    b"\x89PNG", b"GIF8", b"\xff\xd8\xff",    # Images
    b"PK\x03\x04", b"\x1f\x8b",                # Archives
    b"%PDF", b"\x7fELF", b"MZ",               # Documents / executables
    b"RIFF", b"OggS", b"\x1aE\xdf\xa3",       # Media
    b"<?xml", b"<!DOCTYPE", b"<html",          # Markup
    b"-----BEGIN",                              # PEM (already caught by scanner)
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = {c: data.count(c) for c in set(data)}
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_like_binary(text: str) -> bool:
    """Heuristic: does this base64-looking string decode to known binary?"""
    # Try decoding as base64
    try:
        # Add padding if needed
        padded = text
        if len(padded) % 4:
            padded += "=" * (4 - len(padded) % 4)
        decoded = base64.b64decode(padded, validate=True)
        for sig in BINARY_SIGNATURES:
            if decoded.startswith(sig):
                return True
    except Exception:
        pass
    # Check for printable ratio
    printable = sum(1 for c in text if c in string.printable)
    if printable / len(text) < 0.7:
        return True
    return False


def classify_token(value: str) -> str | None:
    """Check if a value matches any known token format. Returns token type or None."""
    for pattern, label in TOKEN_PATTERNS.items():
        if re.fullmatch(pattern, value, re.IGNORECASE):
            return label
    return None


def detect_high_entropy_strings(text: str) -> list[dict]:
    """
    Scan text for high-entropy strings that look like unknown token formats.
    Returns list of {value_hash, entropy, length, reason}.
    Does NOT return the raw value — only a SHA-256 prefix for verification.
    """
    import hashlib

    findings = []
    # Look for long alphanumeric/base64 strings
    candidate_re = re.compile(r"[A-Za-z0-9+/=_-]{32,256}")
    seen = set()

    for match in candidate_re.finditer(text):
        value = match.group(0)
        if value in seen:
            continue
        seen.add(value)

        # Skip values that are too short or too long
        if len(value) < MIN_TOKEN_LENGTH or len(value) > MAX_TOKEN_LENGTH:
            continue

        # Skip if it matches a known token format (handled by primary scanner)
        if classify_token(value):
            continue

        # Entropy check
        ent = shannon_entropy(value)
        if ent < ENTROPY_THRESHOLD:
            continue

        # Skip binary-looking data
        if looks_like_binary(value):
            continue

        # Skip if it's all digits or all same character
        if value.isdigit() or len(set(value)) < 5:
            continue

        value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]

        alpha_chars = sorted({c for c in value if c.isalpha()})
        findings.append({
            "hash_prefix": value_hash,
            "position": match.start(),
            "length": len(value),
            "entropy": round(ent, 2),
            "charset": "".join(alpha_chars[:10]),
        })

    return findings


def detect_yaml_secrets(text: str) -> list[dict]:
    """Find unquoted secrets in YAML/TOML/properties files."""
    findings = []
    for match in YAML_SECRET_RE.finditer(text):
        key = match.group("key")
        value = match.group("value")
        # Skip if value looks like a reference/variable
        if value.startswith(("$", "${", "{{", "%")):
            continue
        # Skip if value is obviously a placeholder
        if value.lower() in {"example", "changeme", "change_me", "placeholder", "dummy", "xxx", "your_token_here"}:
            continue
        # Skip if value is purely numeric or boolean
        if value.lower() in {"true", "false", "yes", "no", "none", "null"}:
            continue
        if value.isdigit():
            continue
        findings.append({
            "key": key,
            "value_length": len(value),
            "line": text[:match.start()].count("\n") + 1,
        })
    return findings


def redact_line(line: str) -> str:
    """
    Redact all known token formats and high-entropy strings from a line.
    Returns the redacted line.
    """
    import hashlib

    # Step 1: Generic key="value" / key='value' assignment redaction
    # Covers patterns the specific token handlers might miss
    generic_secret_re = re.compile(
        r"(?i)(\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|"
        r"private[_-]?key|access[_-]?key)\b\s*[:=]\s*[\"'])([^\"']{8,})([\"'])"
    )
    def _generic_replacer(m):
        return f"{m.group(1)}***redacted***{m.group(3)}"
    line = generic_secret_re.sub(_generic_replacer, line)

    # Step 2: Specific known token format redaction
    for pattern, label in TOKEN_PATTERNS.items():
        compiled = re.compile(pattern, re.IGNORECASE)

        def _replacer(m, label=label):
            value = m.group(0)
            if len(value) <= 8:
                return value
            return f"{value[:4]}...{value[-4:]} [{label}]"

        line = compiled.sub(_replacer, line)

    # Redact YAML unquoted secrets
    def _yaml_replacer(m):
        key = m.group("key")
        value = m.group("value")
        if len(value) <= 4:
            return m.group(0)
        return f"{key}: ***redacted***"

    line = YAML_SECRET_RE.sub(_yaml_replacer, line)

    return line


def redact_and_classify(text: str) -> tuple[str, list[dict]]:
    """
    Full redaction pass. Returns (redacted_text, token_findings).
    token_findings contains classified tokens without raw values.
    """
    findings = []
    redacted = text

    for pattern, label in TOKEN_PATTERNS.items():
        compiled = re.compile(pattern, re.IGNORECASE)

        matches = []
        def _collect(m, label=label):
            import hashlib
            value = m.group(0)
            value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
            matches.append({
                "type": label,
                "hash_prefix": value_hash,
                "position": m.start(),
                "length": len(value),
            })
            if len(value) <= 8:
                return value
            return f"{value[:4]}...{value[-4:]} [{label}]"

        redacted = compiled.sub(_collect, redacted)
        findings.extend(matches)

    return redacted, findings

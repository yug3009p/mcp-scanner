"""Hardcoded secret scanner — regex + Shannon entropy.

Hybrid detector: tight regexes for well-known providers (the high-signal
short keys) plus a generic entropy gate for long random-looking strings
(catches custom keys and rotated tokens). Mapped to OWASP LLM02:2025
(Sensitive Information Disclosure) and CWE-798.
"""

from __future__ import annotations

import math
import re
from typing import Any

# Provider-anchored regexes — each tuple is (label, regex, severity_hint)
_KNOWN_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key ID",     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),              "Critical"),
    ("AWS Secret Access Key", re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^\n]{0,5}['\"][A-Za-z0-9/+=]{40}['\"]"), "Critical"),
    ("GitHub PAT",            re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),           "Critical"),
    ("GitHub OAuth",          re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),           "Critical"),
    ("GitHub App Token",      re.compile(r"\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b"),   "Critical"),
    ("GitHub Refresh Token",  re.compile(r"\bghr_[A-Za-z0-9]{76}\b"),           "Critical"),
    ("Slack Bot Token",       re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  "Critical"),
    ("Slack Webhook",         re.compile(r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+\b"), "High"),
    ("Google API Key",        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),        "Critical"),
    ("Stripe Live Key",       re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), "Critical"),
    ("Stripe Test Key",       re.compile(r"\b(?:sk|rk)_test_[0-9a-zA-Z]{24,}\b"), "High"),
    ("OpenAI API Key",        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), "Critical"),
    ("Anthropic API Key",     re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),    "Critical"),
    ("Groq API Key",          re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"),          "Critical"),
    ("Hugging Face Token",    re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),           "High"),
    ("Twilio Account SID",    re.compile(r"\bAC[a-f0-9]{32}\b"),                "High"),
    ("Twilio Auth Token",     re.compile(r"(?i)twilio.{0,20}auth.{0,5}[\"'][a-f0-9]{32}[\"']"), "Critical"),
    ("Mailgun API Key",       re.compile(r"\bkey-[a-f0-9]{32}\b"),              "High"),
    ("SendGrid API Key",      re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "Critical"),
    ("Square Access Token",   re.compile(r"\bsq0atp-[A-Za-z0-9_\-]{22}\b"),     "Critical"),
    ("npm Token",             re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),           "Critical"),
    ("PyPI Token",            re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"), "Critical"),
    ("Private Key Header",    re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "Critical"),
    ("JWT",                   re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "High"),
    ("Database Connection URL", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/]+:[^\s@/]+@[^\s/]+"), "Critical"),
    ("Generic Bearer Token",  re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}"), "Medium"),
]

# Keys whose value is suspicious by *name* — these always entropy-check
_SUSPICIOUS_KEY_NAMES = re.compile(
    r"(?i)\b(api[_\-]?key|access[_\-]?key|secret|password|passwd|pwd|token|"
    r"client[_\-]?secret|auth|credential|private[_\-]?key|encryption[_\-]?key|"
    r"db[_\-]?password|database[_\-]?url|connection[_\-]?string)\b"
)

# Whitelist substrings — common placeholders that mean "no real secret here"
_PLACEHOLDER_SUBSTRINGS = [
    "your_", "your-", "example", "placeholder", "changeme", "redacted",
    "xxxxxx", "********", "...", "<your", "<insert", "dummy", "test_only",
    "n/a", "null", "none", "false", "true",
]

_ENTROPY_THRESHOLD_HEX = 3.0
_ENTROPY_THRESHOLD_B64 = 4.0
_MIN_SUSPECT_LEN = 16


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def _is_placeholder(value: str) -> bool:
    lower = value.lower()
    if any(p in lower for p in _PLACEHOLDER_SUBSTRINGS):
        return True
    if value.startswith(("${", "{{")) and value.endswith(("}", "}}")):
        return True
    if re.fullmatch(r"\$[A-Z_][A-Z0-9_]*", value):  # ${ENV_VAR}
        return True
    if value in {"", " ", "-", "—", "•"}:
        return True
    return False


def _is_high_entropy(value: str) -> bool:
    if len(value) < _MIN_SUSPECT_LEN:
        return False
    # Hex-only strings are checked with a lower bar
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return _shannon_entropy(value) >= _ENTROPY_THRESHOLD_HEX
    # Base64-ish strings
    if re.fullmatch(r"[A-Za-z0-9+/=_\-]+", value):
        return _shannon_entropy(value) >= _ENTROPY_THRESHOLD_B64
    return False


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _make_finding(
    label: str,
    value: str,
    location: str,
    severity: str,
    detection: str,
) -> dict[str, Any]:
    score_map = {"Critical": 9.8, "High": 8.6, "Medium": 6.5, "Low": 4.0}
    return {
        "id": f"MCP-SEC-{abs(hash(location + value)) % 10000:04d}",
        "scanner": "secrets_scanner",
        "category": "Hardcoded Secrets",
        "title": f"{label} hardcoded in `{location}`",
        "severity": severity,
        "cvss_score": score_map.get(severity, 6.5),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "owasp_llm": "LLM02:2025 — Sensitive Information Disclosure",
        "owasp_agentic": "AAI07:2025 — Identity / Credential Compromise",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "component": location,
        "evidence": f"{label}: {_redact(value)} ({detection})",
        "scenario": (
            f"A {label.lower()} is embedded directly inside `{location}`. "
            "Anyone with read access to the config — including the LLM "
            "itself once the file is loaded into context — obtains the "
            "credential. If the config is committed to git or shared in a "
            "support ticket, the secret is permanently leaked. Recent "
            "incidents (CVE-2025-32711 EchoLeak, Slack-MCP leaks of Q1 "
            "2025) all originated in this exact pattern."
        ),
        "remediation": [
            "Remove the hardcoded value and reference an environment variable instead (e.g., `${API_KEY}`).",
            "Rotate this credential immediately — assume it is compromised.",
            "Add the secret pattern to your pre-commit and CI secret-scanning (gitleaks, trufflehog).",
            "Use a secret manager (1Password, HashiCorp Vault, AWS Secrets Manager) rather than .env files for production agents.",
            "Revoke any access logs that reference this credential before rotation.",
        ],
        "_llm_assist": False,
    }


def _walk(node: Any, path: str, findings: list[dict[str, Any]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            sub = f"{path}.{key}" if path else key
            if isinstance(value, str):
                _check_value(key, value, sub, findings)
            else:
                _walk(value, sub, findings)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            sub = f"{path}[{idx}]"
            if isinstance(value, str):
                _check_value("", value, sub, findings)
            else:
                _walk(value, sub, findings)


def _check_value(
    key_name: str,
    value: str,
    location: str,
    findings: list[dict[str, Any]],
) -> None:
    if not isinstance(value, str) or _is_placeholder(value):
        return

    # Known-provider patterns: search inside the string in case it's embedded
    for label, pattern, sev in _KNOWN_PATTERNS:
        match = pattern.search(value)
        if match:
            findings.append(_make_finding(
                label=label,
                value=match.group(0),
                location=location,
                severity=sev,
                detection="regex match",
            ))

    # Suspicious-key + high-entropy: a custom secret not matching any provider
    if _SUSPICIOUS_KEY_NAMES.search(key_name) and _is_high_entropy(value):
        already_flagged = any(f["component"] == location for f in findings)
        if not already_flagged:
            findings.append(_make_finding(
                label=f"Likely credential in `{key_name}`",
                value=value,
                location=location,
                severity="High",
                detection=f"entropy={_shannon_entropy(value):.2f}",
            ))


def scan_secrets(config: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    _walk(config, "", findings)
    return findings

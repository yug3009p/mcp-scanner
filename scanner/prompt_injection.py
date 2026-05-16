"""Prompt injection surface scanner.

Identifies fields and patterns in an MCP configuration where untrusted
external input flows into LLM context — the foundational class of attack
described in OWASP LLM01:2025 (Prompt Injection) and OWASP Agentic AAI01.
"""

from __future__ import annotations

import re
from typing import Any

from scanner.cvss import cvss_for_profile

# Patterns associated with prompt-injection attempts already baked into a config.
# These are paraphrased from real PI payloads catalogued in OWASP and academic
# datasets (Greshake et al., 2024; Kang et al., 2024).
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore (?:all |the |any )?(?:previous|prior|above) (?:instructions|rules|prompts)",
     "Override instruction injection"),
    (r"disregard (?:the |all |any )?(?:previous|prior|above|earlier) (?:instructions|rules)",
     "Override instruction injection"),
    (r"forget (?:everything|all|your)\b",
     "Memory wipe injection"),
    (r"you are now (?:a|an|in|the)",
     "Role-hijack injection"),
    (r"new instructions?:",
     "Injected directive header"),
    (r"system\s*[:>]\s*",
     "Fake system-role marker"),
    (r"</?(?:system|assistant|user)\s*>",
     "Chat-template tag injection"),
    (r"\b(?:do not|don't) (?:tell|inform|reveal|warn) (?:the user|anyone)",
     "Covert action directive"),
    (r"reveal (?:your |the )?(?:system )?prompt",
     "System-prompt exfiltration request"),
    (r"print (?:your |the )?(?:initial|system|hidden) (?:instructions|prompt)",
     "Prompt exfiltration request"),
    (r"<\|im_start\|>|<\|im_end\|>",
     "ChatML control-token injection"),
    (r"###\s*(?:instruction|system|prompt)\b",
     "Instruction-marker injection"),
    (r"jailbreak|DAN mode|developer mode",
     "Known jailbreak persona"),
]

# Field paths that, by convention, accept untrusted content and feed it to the
# model. Flag these even without a payload because they widen the attack
# surface and require sanitisation.
_UNTRUSTED_SOURCES = {
    "fetch", "http", "web", "browser", "search", "rss",
    "email", "imap", "gmail", "outlook",
    "slack", "discord", "telegram",
    "github", "gitlab", "issues",
    "calendar", "drive",
    "database", "sql", "query",
}


def _flag_text(text: str, location: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(text, str):
        return findings
    lowered = text.lower()
    for pattern, label in _INJECTION_PATTERNS:
        match = re.search(pattern, lowered, re.IGNORECASE)
        if match:
            cvss = cvss_for_profile("prompt_injection")
            findings.append({
                "id": f"MCP-PI-{abs(hash(location + pattern)) % 10000:04d}",
                "scanner": "prompt_injection",
                "category": "Prompt Injection Surface",
                "title": f"{label} detected in {location}",
                "severity": cvss.severity,
                "cvss_score": cvss.base_score,
                "cvss_vector": cvss.vector,
                "owasp_llm": "LLM01:2025 — Prompt Injection",
                "owasp_agentic": "AAI01:2025 — Memory Poisoning / Instruction Hijack",
                "cwe": "CWE-1427: Improper Neutralization of Input in LLM Prompts",
                "component": location,
                "evidence": match.group(0),
                "scenario": (
                    f"The string `{match.group(0)}` appears inside `{location}`. "
                    "When the agent renders this field into model context, the "
                    "injected directive can override the original system "
                    "instructions, causing the agent to leak data, take "
                    "unauthorized tool actions, or impersonate trusted roles."
                ),
                "remediation": [
                    "Treat tool descriptions and external content as data, not instructions.",
                    "Wrap untrusted content in delimited blocks and enforce 'instructions outside the block are not authoritative' in your system prompt.",
                    "Run an instruction-classifier (e.g., Lakera/Prompt Guard) on all tool descriptions and ingest fields before they reach the model.",
                    "Sign and pin tool descriptions; reject changes that introduce new imperative verbs.",
                ],
                "_llm_assist": False,
            })
    return findings


def _walk(node: Any, path: str, findings: list[dict[str, Any]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            sub = f"{path}.{key}" if path else key
            if isinstance(value, str):
                findings.extend(_flag_text(value, sub))
            else:
                _walk(value, sub, findings)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            _walk(value, f"{path}[{idx}]", findings)
    elif isinstance(node, str):
        findings.extend(_flag_text(node, path))


def _has_isolation_guard(server: dict) -> bool:
    """Server is considered guarded if it has auth + a constrained egress list."""
    has_auth = bool(
        server.get("auth")
        or server.get("api_key")
        or server.get("bearer_token")
        or server.get("oauth")
    )
    egress = (
        server.get("network", {}).get("egress")
        if isinstance(server.get("network"), dict)
        else server.get("egress")
    )
    constrained_egress = isinstance(egress, list) and len(egress) >= 0 and all(
        isinstance(e, str) and e not in {"0.0.0.0/0", "::/0", "*"} for e in egress
    )
    return has_auth and constrained_egress


def _flag_untrusted_sources(config: dict, findings: list[dict[str, Any]]) -> None:
    servers = config.get("mcpServers", {}) or config.get("servers", {}) or {}
    if not isinstance(servers, dict):
        return
    for server_name, server in servers.items():
        if not isinstance(server, dict):
            continue
        if _has_isolation_guard(server):
            continue
        haystack = " ".join(
            str(v) for v in [
                server_name,
                server.get("command", ""),
                " ".join(server.get("args", []) if isinstance(server.get("args"), list) else []),
                server.get("description", ""),
                server.get("url", ""),
            ]
        ).lower()
        hits = sorted({src for src in _UNTRUSTED_SOURCES if src in haystack})
        if hits:
            cvss = cvss_for_profile("prompt_injection")
            findings.append({
                "id": f"MCP-PI-SRC-{abs(hash(server_name)) % 10000:04d}",
                "scanner": "prompt_injection",
                "category": "Prompt Injection Surface",
                "title": f"Untrusted-input source `{server_name}` lacks isolation guard",
                "severity": "Medium" if cvss.severity == "Critical" else cvss.severity,
                "cvss_score": min(cvss.base_score, 6.4),
                "cvss_vector": cvss.vector,
                "owasp_llm": "LLM01:2025 — Prompt Injection",
                "owasp_agentic": "AAI01:2025 — Instruction Hijack via External Data",
                "cwe": "CWE-1426: Improper Validation of Generative AI Output",
                "component": f"mcpServers.{server_name}",
                "evidence": ", ".join(hits),
                "scenario": (
                    f"Server `{server_name}` ingests content from {', '.join(hits)} — "
                    "channels controlled by third parties. Without an instruction "
                    "boundary or output filter, an attacker can plant directives in "
                    "an email, issue, or web page that the agent then executes as if "
                    "issued by the user."
                ),
                "remediation": [
                    "Tag this server's outputs as 'untrusted' in the agent's tool router.",
                    "Strip or escape control tokens (`<|im_start|>`, role markers) before model ingestion.",
                    "Disallow chained tool calls from this server to high-privilege tools without human confirmation.",
                    "Add an output classifier that blocks responses containing imperative verbs targeting other tools.",
                ],
                "_llm_assist": False,
            })


def scan_prompt_injection(config: dict) -> list[dict[str, Any]]:
    """Scan a parsed MCP config for prompt-injection surfaces and payloads."""
    findings: list[dict[str, Any]] = []
    _walk(config, "", findings)
    _flag_untrusted_sources(config, findings)
    return findings

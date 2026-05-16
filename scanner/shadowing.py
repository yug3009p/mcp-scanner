"""Cross-tool shadowing scanner.

When two MCP servers expose tools with the same (or near-identical) names,
the agent's tool router becomes non-deterministic. An attacker who controls
one server can shadow a trusted tool — the agent may dispatch a `read_file`
call to a poisoned server instead of the legitimate one. Tracked under
OWASP Agentic AAI04 (Tool Misuse) and AAI10 (Overreliance on Agent Output).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from scanner.cvss import cvss_for_profile

# Tool names that, if shadowed, give an attacker maximum leverage
_HIGH_VALUE_NAMES = {
    "read_file", "write_file", "list_directory", "delete_file",
    "exec", "execute", "shell", "run_command",
    "send_email", "send_message",
    "git_commit", "git_push", "git_clone",
    "create_pr", "merge_pr",
    "transfer", "pay", "purchase",
    "approve", "authenticate", "authorize",
}

_NORMALISE_RE = re.compile(r"[\s_\-]+")


def _normalise(name: str) -> str:
    return _NORMALISE_RE.sub("", name.lower())


def _iter_named_tools(config: dict) -> list[tuple[str, str, str]]:
    """Yield (server_name, tool_name, location) for every tool."""
    out: list[tuple[str, str, str]] = []
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict):
        return out
    for sname, server in servers.items():
        if not isinstance(server, dict):
            continue
        for key in ("tools", "functions", "capabilities"):
            tools = server.get(key, []) or []
            if not isinstance(tools, list):
                continue
            for idx, tool in enumerate(tools):
                if not isinstance(tool, dict):
                    continue
                tname = tool.get("name") or tool.get("function")
                if isinstance(tname, str) and tname:
                    out.append((sname, tname, f"mcpServers.{sname}.{key}[{idx}]"))
    # Top-level tools array (treat as server "__root__")
    for key in ("tools", "functions"):
        tools = config.get(key, []) or []
        if isinstance(tools, list):
            for idx, tool in enumerate(tools):
                if isinstance(tool, dict):
                    tname = tool.get("name") or tool.get("function")
                    if isinstance(tname, str) and tname:
                        out.append(("__root__", tname, f"{key}[{idx}]"))
    return out


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (ca != cb)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def scan_shadowing(config: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    tools = _iter_named_tools(config)
    if not tools:
        return findings

    # Group by normalised name to detect exact/case/separator collisions
    groups: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for sname, tname, loc in tools:
        groups[_normalise(tname)].append((sname, tname, loc))

    for norm, occurrences in groups.items():
        if len(occurrences) < 2:
            continue
        servers_involved = sorted({s for s, _, _ in occurrences})
        if len(servers_involved) < 2:
            continue
        is_high_value = norm in {_normalise(n) for n in _HIGH_VALUE_NAMES}
        cvss = cvss_for_profile("tool_shadowing")
        names_shown = sorted({t for _, t, _ in occurrences})
        findings.append({
            "id": f"MCP-SHADOW-{abs(hash(norm)) % 10000:04d}",
            "scanner": "shadowing",
            "category": "Cross-Tool Shadowing",
            "title": f"Tool name `{names_shown[0]}` exposed by {len(servers_involved)} servers",
            "severity": "Critical" if is_high_value else "High",
            "cvss_score": 8.7 if is_high_value else 7.1,
            "cvss_vector": cvss.vector,
            "owasp_llm": "LLM06:2025 — Excessive Agency",
            "owasp_agentic": "AAI04:2025 — Tool Misuse via Shadowing",
            "cwe": "CWE-1023: Incomplete Comparison with Missing Factors",
            "component": ", ".join(loc for _, _, loc in occurrences),
            "evidence": (
                f"Names: {', '.join(names_shown)} | "
                f"Servers: {', '.join(servers_involved)}"
            ),
            "scenario": (
                f"`{names_shown[0]}` is published by {', '.join(servers_involved)}. "
                "The agent's tool router selects by name, so the model's choice "
                "between identically-named tools is influenced by description "
                "wording rather than provenance. An attacker who controls (or "
                "poisons) one server can intercept calls intended for the "
                "trusted one — a classic tool-shadowing attack as described in "
                "the MCP security taxonomy (Invariant, 2025)."
            ) + (
                " Because this name targets a high-impact primitive, exploitation "
                "yields direct data exfiltration or code execution."
                if is_high_value else ""
            ),
            "remediation": [
                "Namespace tool names by server (e.g., `git.read_file` vs `s3.read_file`).",
                "Enable strict-mode tool routing in your MCP client: require the model to specify `server.tool`.",
                "Audit each server's intent; remove duplicates not needed for the workflow.",
                "Surface tool provenance (server name + signature) in every tool invocation prompt.",
            ],
            "_llm_assist": False,
        })

    # Near-misses — typosquats within the same config (edit distance ≤ 2)
    all_pairs = [(s, t) for s, t, _ in tools]
    seen_pairs = set()
    for i, (s1, t1) in enumerate(all_pairs):
        for s2, t2 in all_pairs[i + 1:]:
            if s1 == s2 or t1 == t2:
                continue
            n1, n2 = _normalise(t1), _normalise(t2)
            if n1 == n2:
                continue  # already caught by exact collision above
            if min(len(n1), len(n2)) < 6:
                continue
            dist = _levenshtein(n1, n2)
            if 0 < dist <= 2:
                key = tuple(sorted((t1, t2)))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                findings.append({
                    "id": f"MCP-SHADOW-TYPO-{abs(hash(str(key))) % 10000:04d}",
                    "scanner": "shadowing",
                    "category": "Cross-Tool Shadowing",
                    "title": f"Near-duplicate tool names `{t1}` / `{t2}` across servers",
                    "severity": "Medium",
                    "cvss_score": 5.7,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N",
                    "owasp_llm": "LLM06:2025 — Excessive Agency",
                    "owasp_agentic": "AAI04:2025 — Tool Misuse via Shadowing",
                    "cwe": "CWE-1023",
                    "component": f"{s1}:{t1} <> {s2}:{t2}",
                    "evidence": f"levenshtein distance = {dist}",
                    "scenario": (
                        f"`{t1}` and `{t2}` differ by {dist} characters across "
                        f"servers `{s1}` and `{s2}`. The model may select the "
                        "wrong tool through a transcription or spelling error in "
                        "its own chain-of-thought, leaking data to the wrong "
                        "endpoint without anyone noticing."
                    ),
                    "remediation": [
                        "Rename one of the tools to a clearly distinct identifier.",
                        "Document the intended workflow per tool in your runbook.",
                        "Log every tool selection with the server identifier and review weekly.",
                    ],
                    "_llm_assist": False,
                })
    return findings

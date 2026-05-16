"""Authentication & scope-control scanner.

Flags MCP servers exposing dangerous tools without any authentication,
scope restriction, or rate limit. Maps to OWASP LLM06:2025 (Excessive
Agency), OWASP Agentic AAI05 (Cascading Failures), and CWE-306 (Missing
Authentication for Critical Function).
"""

from __future__ import annotations

from typing import Any

from scanner.cvss import cvss_for_profile

# Tool name fragments that imply a state-changing or sensitive operation
_DANGEROUS_TOOL_HINTS = [
    "write", "delete", "remove", "drop", "truncate",
    "exec", "execute", "shell", "run_command", "eval",
    "send_email", "send_message", "post_message",
    "git_push", "git_commit", "create_pr", "merge",
    "transfer", "pay", "charge", "refund", "purchase",
    "deploy", "rollback", "scale", "terminate",
    "create_user", "delete_user", "grant", "revoke",
    "approve", "authenticate_as", "impersonate",
]

# Field names that, if present and non-empty, indicate auth is configured
_AUTH_FIELDS = [
    "auth", "authentication", "authorization",
    "api_key", "apikey", "api_key_env", "api_key_ref",
    "bearer_token", "oauth", "oauth2",
    "client_credentials", "credentials",
    "scopes", "scope", "permissions",
    "headers",  # bearer tokens often live here
]


def _has_auth(server: dict) -> bool:
    for field in _AUTH_FIELDS:
        value = server.get(field)
        if not value:
            continue
        # Empty dict / empty list / empty string => not configured
        if isinstance(value, dict) and not value:
            continue
        if isinstance(value, list) and not value:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        # `headers` only counts if it carries an Authorization-ish header
        if field == "headers" and isinstance(value, dict):
            if not any(
                isinstance(k, str) and (
                    k.lower() == "authorization"
                    or "api-key" in k.lower()
                    or "token" in k.lower()
                )
                for k in value.keys()
            ):
                continue
        return True
    return False


def _is_dangerous(tool: dict) -> tuple[bool, list[str]]:
    if not isinstance(tool, dict):
        return False, []
    haystack = (
        " ".join(
            str(tool.get(k, ""))
            for k in ("name", "function", "description", "operation")
        )
    ).lower()
    hits = [h for h in _DANGEROUS_TOOL_HINTS if h in haystack]
    return bool(hits), hits


def _is_remote(server: dict) -> bool:
    """Heuristic: server is remote-exposed if it declares a URL or HTTP transport."""
    if server.get("url") or server.get("endpoint"):
        return True
    transport = (server.get("transport") or "").lower()
    if transport in {"http", "https", "sse", "websocket", "ws", "wss"}:
        return True
    return False


def scan_authentication(config: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict):
        return findings

    for server_name, server in servers.items():
        if not isinstance(server, dict):
            continue
        has_auth = _has_auth(server)
        is_remote = _is_remote(server)

        dangerous_tools: list[tuple[str, list[str]]] = []
        for key in ("tools", "functions", "capabilities"):
            for tool in server.get(key, []) or []:
                if not isinstance(tool, dict):
                    continue
                ok, hits = _is_dangerous(tool)
                if ok:
                    dangerous_tools.append((tool.get("name", "<unnamed>"), hits))

        # 1) Dangerous tools with no auth — Critical
        if dangerous_tools and not has_auth:
            cvss = cvss_for_profile("missing_auth")
            tool_names = ", ".join(n for n, _ in dangerous_tools[:5])
            findings.append({
                "id": f"MCP-AUTH-{abs(hash(server_name)) % 10000:04d}",
                "scanner": "auth_scanner",
                "category": "Missing Authentication",
                "title": f"Server `{server_name}` exposes write/exec tools with no auth",
                "severity": "Critical",
                "cvss_score": cvss.base_score,
                "cvss_vector": cvss.vector,
                "owasp_llm": "LLM06:2025 — Excessive Agency",
                "owasp_agentic": "AAI05:2025 — Cascading Failures / Trust Boundary Violation",
                "cwe": "CWE-306: Missing Authentication for Critical Function",
                "component": f"mcpServers.{server_name}",
                "evidence": f"State-changing tools without auth: {tool_names}",
                "scenario": (
                    f"`{server_name}` declares tools that modify state or "
                    f"execute code ({tool_names}) yet defines no `auth`, "
                    "`api_key`, or scope field. Any process or user able to "
                    "reach this server (locally or, if exposed, over the "
                    "network) can invoke those tools. With a remote-exposed "
                    "MCP server this is functionally a back door."
                ),
                "remediation": [
                    "Add an `auth` block referencing an env-var token: `auth: { type: bearer, token_env: SERVER_TOKEN }`.",
                    "Restrict callable tools by scope (e.g., scope `write` required for `git_push`).",
                    "If exposed over the network, terminate TLS and require mTLS or OAuth client-credentials.",
                    "Add an audit log for every tool call with caller identity.",
                ],
                "_llm_assist": False,
            })

        # 2) Remote server with no auth (regardless of tool sensitivity) — High
        if is_remote and not has_auth:
            cvss = cvss_for_profile("missing_auth")
            findings.append({
                "id": f"MCP-AUTH-REMOTE-{abs(hash(server_name)) % 10000:04d}",
                "scanner": "auth_scanner",
                "category": "Missing Authentication",
                "title": f"Remote server `{server_name}` accepts unauthenticated connections",
                "severity": "High",
                "cvss_score": min(cvss.base_score, 8.2),
                "cvss_vector": cvss.vector,
                "owasp_llm": "LLM06:2025 — Excessive Agency",
                "owasp_agentic": "AAI05:2025 — Cascading Failures",
                "cwe": "CWE-306",
                "component": f"mcpServers.{server_name}",
                "evidence": f"transport={server.get('transport')} url={server.get('url')}",
                "scenario": (
                    f"`{server_name}` is reachable over the network "
                    f"({server.get('transport') or server.get('url')}) yet "
                    "performs no caller authentication. Anyone with network "
                    "reachability — including a poisoned agent in the same "
                    "trust zone — can enumerate and call every tool the "
                    "server exposes."
                ),
                "remediation": [
                    "Require an authenticator before serving any RPC; reject anonymous calls at the framework layer.",
                    "Bind to localhost only unless intentional remote use is documented.",
                    "Layer a reverse-proxy with an authn header check (e.g., oauth2-proxy).",
                ],
                "_llm_assist": False,
            })

        # 3) Auth field exists but is a literal placeholder — Medium
        for field in ("api_key", "token", "bearer_token"):
            val = server.get(field)
            if isinstance(val, str) and val and (
                val.lower() in {"changeme", "placeholder", "todo", "xxx", "yourkey"}
                or "your_" in val.lower()
            ):
                findings.append({
                    "id": f"MCP-AUTH-PLACE-{abs(hash(server_name + field)) % 10000:04d}",
                    "scanner": "auth_scanner",
                    "category": "Missing Authentication",
                    "title": f"`{server_name}.{field}` is a placeholder value",
                    "severity": "Medium",
                    "cvss_score": 5.9,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "owasp_llm": "LLM06:2025 — Excessive Agency",
                    "owasp_agentic": "AAI05:2025 — Cascading Failures",
                    "cwe": "CWE-1188: Insecure Default Initialization of Resource",
                    "component": f"mcpServers.{server_name}.{field}",
                    "evidence": f"{field}={val}",
                    "scenario": (
                        "The auth field is wired but contains an unmistakable "
                        "placeholder. In practice this either fails closed "
                        "(server unreachable) or — worse — fails open if the "
                        "server treats the placeholder as a valid identifier."
                    ),
                    "remediation": [
                        "Replace the placeholder with `${ENV_VAR_NAME}` and inject from a secret store.",
                        "Add a startup check that refuses to launch if the auth value matches a placeholder regex.",
                    ],
                    "_llm_assist": False,
                })

    return findings

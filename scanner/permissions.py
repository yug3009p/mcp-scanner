"""Overly-broad permissions scanner.

Flags filesystem mounts, network egress rules, and command allow-lists that
grant the MCP server materially more access than a typical workflow requires.
Mapped to OWASP LLM06:2025 (Excessive Agency) and OWASP Agentic AAI03
(Privilege Compromise).
"""

from __future__ import annotations

import re
from typing import Any

from scanner.cvss import cvss_for_profile

# Filesystem roots that should never be exposed wholesale
_DANGEROUS_FS_ROOTS = [
    "/",
    "/etc",
    "/etc/",
    "/root",
    "/root/",
    "/home",
    "/var",
    "/var/log",
    "/usr",
    "/usr/local",
    "C:\\",
    "C:/",
    "C:\\Windows",
    "C:\\Users",
    "C:/Users",
    "~",
    "~/",
    "$HOME",
    "${HOME}",
    "%USERPROFILE%",
]

# Args that, on common reference MCP servers, indicate full-disk scope
_DANGEROUS_FS_FLAGS = ["--allow-all", "--no-sandbox", "--full-access", "-r", "--recursive"]

# Network scopes that imply unrestricted egress
_DANGEROUS_NET_PATTERNS = [
    (r"^0\.0\.0\.0/0$", "All IPv4 hosts"),
    (r"^::/0$", "All IPv6 hosts"),
    (r"^\*$", "Wildcard host"),
    (r"^\*\.\*$", "Wildcard domain"),
    (r"^https?://\*", "Wildcard HTTP origin"),
    (r"^\*://", "Any protocol"),
]

# Shell-exec capabilities are first-class danger
_DANGEROUS_COMMANDS = {
    "sh", "bash", "zsh", "powershell", "pwsh", "cmd", "cmd.exe",
    "python", "python3", "node", "deno", "ruby", "perl",
    "eval", "exec", "spawn",
}


def _check_filesystem(server_name: str, server: dict, findings: list[dict[str, Any]]) -> None:
    args = server.get("args", [])
    if not isinstance(args, list):
        args = []
    command = (server.get("command") or "").lower()
    is_fs = "filesystem" in server_name.lower() or "filesystem" in command or any(
        "filesystem" in str(a).lower() for a in args
    )

    paths_seen: list[str] = []
    for arg in args:
        if not isinstance(arg, str):
            continue
        if arg in _DANGEROUS_FS_ROOTS or arg.rstrip("/\\") in {r.rstrip("/\\") for r in _DANGEROUS_FS_ROOTS}:
            paths_seen.append(arg)
        if arg in _DANGEROUS_FS_FLAGS:
            paths_seen.append(arg)

    # Inspect declared mounts
    for mount in server.get("mounts", []) or []:
        if isinstance(mount, str) and mount in _DANGEROUS_FS_ROOTS:
            paths_seen.append(mount)
        if isinstance(mount, dict):
            path = mount.get("path") or mount.get("source") or ""
            if path in _DANGEROUS_FS_ROOTS:
                paths_seen.append(path)

    if paths_seen:
        cvss = cvss_for_profile("broad_filesystem")
        findings.append({
            "id": f"MCP-PERM-FS-{abs(hash(server_name)) % 10000:04d}",
            "scanner": "permissions",
            "category": "Overly Broad Permissions",
            "title": f"Server `{server_name}` exposes filesystem root(s) {', '.join(paths_seen[:3])}",
            "severity": "Critical" if any(p in {"/", "C:\\", "C:/", "/root", "$HOME", "%USERPROFILE%"} for p in paths_seen) else "High",
            "cvss_score": cvss.base_score,
            "cvss_vector": cvss.vector,
            "owasp_llm": "LLM06:2025 — Excessive Agency",
            "owasp_agentic": "AAI03:2025 — Privilege Compromise",
            "cwe": "CWE-732: Incorrect Permission Assignment for Critical Resource",
            "component": f"mcpServers.{server_name}.args",
            "evidence": ", ".join(paths_seen),
            "scenario": (
                f"`{server_name}` is configured with read/write access to "
                f"{', '.join(paths_seen[:3])}. A single prompt-injection or "
                "poisoned tool call can now read SSH keys, browser cookies, "
                "cloud credentials, or replace binaries on PATH. The blast "
                "radius of any other vulnerability in the agent chain is "
                "multiplied by this permission grant."
            ),
            "remediation": [
                "Mount only the specific subdirectory the workflow needs (principle of least privilege).",
                "Prefer read-only mounts unless write access is unavoidable.",
                "Use OS-level sandboxing (Docker, Bubblewrap, AppArmor) so the agent cannot escape the declared path.",
                "Add a path-whitelist filter in the MCP client before forwarding tool calls.",
                f"Replace `{', '.join(paths_seen[:2])}` with the smallest viable scope, e.g. `~/Projects/<repo>`.",
            ],
            "_llm_assist": False,
        })

    # Filesystem server with no args at all = unrestricted by default
    if is_fs and not args:
        cvss = cvss_for_profile("broad_filesystem")
        findings.append({
            "id": f"MCP-PERM-FS-{abs(hash(server_name + 'noarg')) % 10000:04d}",
            "scanner": "permissions",
            "category": "Overly Broad Permissions",
            "title": f"Filesystem server `{server_name}` has no path restrictions",
            "severity": "High",
            "cvss_score": min(cvss.base_score, 8.4),
            "cvss_vector": cvss.vector,
            "owasp_llm": "LLM06:2025 — Excessive Agency",
            "owasp_agentic": "AAI03:2025 — Privilege Compromise",
            "cwe": "CWE-732",
            "component": f"mcpServers.{server_name}",
            "evidence": "args list empty or missing",
            "scenario": (
                "Most filesystem MCP implementations default to the process "
                "working directory when no path is supplied, which on a "
                "developer workstation usually inherits the user's full home "
                "directory tree. The server effectively grants whole-user-account "
                "file access."
            ),
            "remediation": [
                "Pass an explicit allowed path: e.g. `args: ['/srv/agent-workspace']`.",
                "Document the intended scope in the config and refuse to start without it.",
            ],
            "_llm_assist": False,
        })


def _check_network(server_name: str, server: dict, findings: list[dict[str, Any]]) -> None:
    egress = (
        server.get("network", {}).get("egress")
        or server.get("egress")
        or server.get("allowed_hosts")
        or []
    )
    if isinstance(egress, str):
        egress = [egress]
    if not isinstance(egress, list):
        return

    hits: list[tuple[str, str]] = []
    for entry in egress:
        if not isinstance(entry, str):
            continue
        for pattern, label in _DANGEROUS_NET_PATTERNS:
            if re.match(pattern, entry):
                hits.append((entry, label))

    if hits:
        cvss = cvss_for_profile("broad_network")
        findings.append({
            "id": f"MCP-PERM-NET-{abs(hash(server_name)) % 10000:04d}",
            "scanner": "permissions",
            "category": "Overly Broad Permissions",
            "title": f"Server `{server_name}` permits unrestricted network egress",
            "severity": "High",
            "cvss_score": cvss.base_score,
            "cvss_vector": cvss.vector,
            "owasp_llm": "LLM06:2025 — Excessive Agency",
            "owasp_agentic": "AAI03:2025 — Privilege Compromise",
            "cwe": "CWE-918: Server-Side Request Forgery",
            "component": f"mcpServers.{server_name}.egress",
            "evidence": ", ".join(f"{e} ({l})" for e, l in hits),
            "scenario": (
                f"`{server_name}` may originate connections to "
                f"{', '.join(e for e, _ in hits)}. Any indirect prompt "
                "injection turns into data exfiltration: the attacker simply "
                "instructs the agent to POST sensitive findings to a remote "
                "host. The same path enables internal SSRF if the agent runs "
                "inside a corporate network."
            ),
            "remediation": [
                "Replace wildcards with a host allow-list of the exact APIs the workflow needs.",
                "Block RFC1918 ranges to prevent internal SSRF unless explicitly required.",
                "Send all outbound traffic through a logging proxy with allow-listing.",
                "Disable connection-on-demand DNS resolution to known exfiltration suffixes (e.g., *.requestbin.*).",
            ],
            "_llm_assist": False,
        })


def _check_shell(server_name: str, server: dict, findings: list[dict[str, Any]]) -> None:
    command = (server.get("command") or "").strip().lower()
    args = server.get("args", []) or []
    if not isinstance(args, list):
        args = []
    tools = server.get("tools", []) or []
    if not isinstance(tools, list):
        tools = []

    shell_evidence = []
    if command in _DANGEROUS_COMMANDS:
        shell_evidence.append(f"command={command}")
    for arg in args:
        if isinstance(arg, str) and arg.strip().lower() in _DANGEROUS_COMMANDS:
            shell_evidence.append(f"arg={arg}")
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tname = (tool.get("name") or "").lower()
        if tname in {"exec", "shell", "run_command", "eval", "execute"}:
            shell_evidence.append(f"tool={tool.get('name')}")

    if shell_evidence:
        cvss = cvss_for_profile("remote_code_execution")
        findings.append({
            "id": f"MCP-PERM-EXEC-{abs(hash(server_name)) % 10000:04d}",
            "scanner": "permissions",
            "category": "Overly Broad Permissions",
            "title": f"Server `{server_name}` exposes arbitrary command execution",
            "severity": "Critical",
            "cvss_score": cvss.base_score,
            "cvss_vector": cvss.vector,
            "owasp_llm": "LLM06:2025 — Excessive Agency",
            "owasp_agentic": "AAI03:2025 — Privilege Compromise",
            "cwe": "CWE-78: OS Command Injection",
            "component": f"mcpServers.{server_name}",
            "evidence": "; ".join(shell_evidence),
            "scenario": (
                f"`{server_name}` allows the agent to invoke a generic shell "
                "or exec primitive. Any prompt-injection that influences the "
                "tool's argument string becomes arbitrary code execution under "
                "the user's identity. This is the highest-impact MCP "
                "misconfiguration class."
            ),
            "remediation": [
                "Replace the generic exec tool with task-specific tools (e.g., `git_status`, `npm_test`).",
                "If exec is unavoidable, require a static allow-list of binaries and reject shell metacharacters.",
                "Run the server in a container with no network and a read-only root filesystem.",
                "Add an out-of-band confirmation prompt for every shell invocation.",
            ],
            "_llm_assist": False,
        })


def scan_permissions(config: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict):
        return findings
    for server_name, server in servers.items():
        if not isinstance(server, dict):
            continue
        _check_filesystem(server_name, server, findings)
        _check_network(server_name, server, findings)
        _check_shell(server_name, server, findings)
    return findings

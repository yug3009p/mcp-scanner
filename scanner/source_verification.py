"""Unverified MCP server source scanner.

Checks whether each declared server originates from a trusted, signed,
versioned source. Untrusted sources are the supply-chain attack vector
documented in OWASP LLM03:2025 (Supply Chain) and the April 2025
malicious-MCP campaign on npm and PyPI.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from scanner.cvss import cvss_for_profile

# Publishers / hosts considered first-party or audited
_TRUSTED_PUBLISHERS = {
    "@modelcontextprotocol",
    "@anthropic-ai",
    "@anthropic",
    "@cloudflare",
    "@github",
    "@microsoft",
    "@google",
    "@openai",
}
_TRUSTED_HOSTS = {
    "registry.modelcontextprotocol.io",
    "pypi.org",
    "registry.npmjs.org",
    "github.com",
    "api.github.com",
    "ghcr.io",
}

# Hosts known to be reverse-shell / file-drop / paste services — never legit
_BLOCKLIST_HOSTS = {
    "requestbin.com", "requestbin.net", "requestcatcher.com",
    "webhook.site", "ngrok.io", "ngrok-free.app",
    "pastebin.com", "0x0.st", "transfer.sh",
    "burpcollaborator.net", "interact.sh", "oast.fun",
    "discord.com/api/webhooks",
}

# Commands that pull and execute arbitrary code without integrity check
_RISKY_PULL_COMMANDS = {"curl", "wget", "iwr", "invoke-webrequest"}


def _extract_origins(server_name: str, server: dict) -> list[tuple[str, str]]:
    """Return [(kind, value)] tuples — kind ∈ {npm, pip, url, command-arg}."""
    origins: list[tuple[str, str]] = []
    command = (server.get("command") or "").lower()
    args = server.get("args", []) or []

    # npm exec / npx <pkg>
    if command in {"npx", "yarn", "pnpm"}:
        for arg in args:
            if isinstance(arg, str) and not arg.startswith("-"):
                origins.append(("npm", arg))
                break
    # uvx / pipx
    if command in {"uvx", "uv", "pipx", "pip"}:
        for arg in args:
            if isinstance(arg, str) and not arg.startswith("-"):
                origins.append(("pip", arg))
                break
    # docker run <image>
    if command == "docker":
        for arg in args:
            if isinstance(arg, str) and "/" in arg and not arg.startswith("-"):
                origins.append(("docker", arg))
                break
    # Any URL anywhere in command/args
    for blob in [command] + [str(a) for a in args]:
        for m in re.finditer(r"https?://[^\s\"']+", blob):
            origins.append(("url", m.group(0)))

    # Explicit "url" / "registry" / "source" field
    for field in ("url", "registry", "source", "package", "image"):
        val = server.get(field)
        if isinstance(val, str) and val:
            kind = "url" if val.startswith("http") else field
            origins.append((kind, val))

    # Curl/wget piped to shell — the textbook supply-chain anti-pattern
    if command in _RISKY_PULL_COMMANDS:
        origins.append(("pipe-to-shell", " ".join([command] + [str(a) for a in args])))

    return origins


def _is_trusted_npm(pkg: str) -> bool:
    return any(pkg.startswith(p + "/") for p in _TRUSTED_PUBLISHERS) or pkg.startswith("@modelcontextprotocol/")


def _has_integrity_pin(server: dict) -> bool:
    integ = server.get("integrity")
    if isinstance(integ, dict) and any(
        isinstance(v, str) and len(v) >= 32
        for k, v in integ.items()
        if k.lower() in {"sha256", "sha512", "sha1", "digest", "hash"}
    ):
        return True
    if isinstance(integ, str) and len(integ) >= 32:
        return True
    return False


def _check_origin(server_name: str, kind: str, value: str, server: dict) -> dict[str, Any] | None:
    # Pinned-version check: package@1.2.3 is acceptable, package@latest is not
    if kind in {"npm", "pip", "docker"}:
        unpinned = "@latest" in value or "@*" in value or (
            kind == "docker" and ":" not in value
        ) or (
            kind in {"npm", "pip"} and "@" not in value.lstrip("@").split("/")[-1]
        )
        trusted = (kind == "npm" and _is_trusted_npm(value)) or any(
            p.strip("@") in value for p in _TRUSTED_PUBLISHERS
        )
        # An explicit integrity hash mitigates unverified-publisher risk
        if _has_integrity_pin(server):
            trusted = True
        if unpinned:
            return {
                "id": f"MCP-SRC-{abs(hash(server_name + value)) % 10000:04d}",
                "scanner": "source_verification",
                "category": "Unverified Server Source",
                "title": f"`{server_name}` pulls `{value}` without a pinned version",
                "severity": "High",
                "cvss_score": 7.4,
                "cvss_vector": cvss_for_profile("unverified_source").vector,
                "owasp_llm": "LLM03:2025 — Supply Chain",
                "owasp_agentic": "AAI06:2025 — Supply-Chain Compromise",
                "cwe": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
                "component": f"mcpServers.{server_name}",
                "evidence": f"{kind}:{value}",
                "scenario": (
                    f"`{server_name}` resolves `{value}` at runtime against the "
                    "live registry. A publisher takeover, typosquat, or malicious "
                    "version-bump (the April 2025 `@modelcontextprotocol-extras` "
                    "incident, the May 2025 `mcp-tools` PyPI typosquat) will be "
                    "pulled and executed silently. Without integrity pinning, you "
                    "inherit every vulnerability published upstream."
                ),
                "remediation": [
                    "Pin to an exact version: e.g. `package@1.4.2` not `package`.",
                    "Add an integrity hash (npm `--integrity`, pip `--hash`, docker digest `@sha256:...`).",
                    "Mirror trusted versions to a private registry and disable upstream fetch.",
                    "Verify the publisher matches the expected scope (e.g., `@modelcontextprotocol/*`).",
                ],
                "_llm_assist": False,
            }
        if not trusted:
            return {
                "id": f"MCP-SRC-{abs(hash(server_name + value + 'pub')) % 10000:04d}",
                "scanner": "source_verification",
                "category": "Unverified Server Source",
                "title": f"`{server_name}` installs from unverified publisher `{value.split('/')[0]}`",
                "severity": "Medium",
                "cvss_score": 6.1,
                "cvss_vector": cvss_for_profile("unverified_source").vector,
                "owasp_llm": "LLM03:2025 — Supply Chain",
                "owasp_agentic": "AAI06:2025 — Supply-Chain Compromise",
                "cwe": "CWE-494: Download of Code Without Integrity Check",
                "component": f"mcpServers.{server_name}",
                "evidence": f"{kind}:{value}",
                "scenario": (
                    f"The package `{value}` is not published by a known first-party "
                    "MCP scope. Community packages are often valuable but they have "
                    "neither vendor signing nor SLAs around incident response. "
                    "Treat them as untrusted code."
                ),
                "remediation": [
                    "Review the upstream repo, recent commits, and maintainer list before adoption.",
                    "Fork to a vetted internal mirror; pull from the fork only.",
                    "Run the server in an isolated container with no host filesystem access.",
                    "Subscribe to advisories on the package and set a re-review cadence.",
                ],
                "_llm_assist": False,
            }
        return None

    if kind == "url":
        host = urlparse(value).netloc.lower()
        if host in _BLOCKLIST_HOSTS or any(host.endswith("." + b) for b in _BLOCKLIST_HOSTS if "." in b):
            return {
                "id": f"MCP-SRC-BL-{abs(hash(server_name + value)) % 10000:04d}",
                "scanner": "source_verification",
                "category": "Unverified Server Source",
                "title": f"`{server_name}` references known exfiltration host `{host}`",
                "severity": "Critical",
                "cvss_score": 9.6,
                "cvss_vector": cvss_for_profile("remote_code_execution").vector,
                "owasp_llm": "LLM03:2025 — Supply Chain",
                "owasp_agentic": "AAI06:2025 — Supply-Chain Compromise",
                "cwe": "CWE-829",
                "component": f"mcpServers.{server_name}",
                "evidence": value,
                "scenario": (
                    f"The host `{host}` is a known generic-callback / paste / tunnel "
                    "service. No legitimate MCP server should resolve to one of "
                    "these. This is either a misconfiguration sample left over from "
                    "testing or active data exfiltration."
                ),
                "remediation": [
                    "Remove this server immediately and audit who introduced it.",
                    "Rotate any credentials the server had access to.",
                    "Block these hosts at the egress proxy/firewall.",
                ],
                "_llm_assist": False,
            }
        if host and host not in _TRUSTED_HOSTS:
            scheme = urlparse(value).scheme
            return {
                "id": f"MCP-SRC-URL-{abs(hash(server_name + value)) % 10000:04d}",
                "scanner": "source_verification",
                "category": "Unverified Server Source",
                "title": f"`{server_name}` fetches code from non-allowlisted host `{host}`",
                "severity": "High" if scheme == "http" else "Medium",
                "cvss_score": 7.1 if scheme == "http" else 5.4,
                "cvss_vector": cvss_for_profile("unverified_source").vector,
                "owasp_llm": "LLM03:2025 — Supply Chain",
                "owasp_agentic": "AAI06:2025 — Supply-Chain Compromise",
                "cwe": "CWE-494: Download of Code Without Integrity Check",
                "component": f"mcpServers.{server_name}",
                "evidence": value,
                "scenario": (
                    f"`{server_name}` fetches code or configuration from "
                    f"`{host}` ({scheme}). Without TLS pinning and an allow-list, "
                    "a network attacker (or a stolen DNS record) can substitute "
                    "the payload. HTTP URLs are trivially MITM-able."
                ),
                "remediation": [
                    "Replace HTTP with HTTPS and pin a TLS certificate fingerprint or CA.",
                    "Move the source to a vetted internal mirror.",
                    "Add the resolved host to your allow-list (and nothing else).",
                ],
                "_llm_assist": False,
            }
        return None

    if kind == "pipe-to-shell":
        return {
            "id": f"MCP-SRC-CURL-{abs(hash(server_name + value)) % 10000:04d}",
            "scanner": "source_verification",
            "category": "Unverified Server Source",
            "title": f"`{server_name}` uses curl/wget-to-shell installation pattern",
            "severity": "Critical",
            "cvss_score": 9.1,
            "cvss_vector": cvss_for_profile("remote_code_execution").vector,
            "owasp_llm": "LLM03:2025 — Supply Chain",
            "owasp_agentic": "AAI06:2025 — Supply-Chain Compromise",
            "cwe": "CWE-494",
            "component": f"mcpServers.{server_name}",
            "evidence": value[:120],
            "scenario": (
                "Piping remote content directly into a shell interpreter "
                "executes attacker-controlled code with no integrity check, "
                "no provenance, and no version pinning. This pattern is "
                "called out specifically in OWASP A06:2021 and the SLSA "
                "supply-chain spec."
            ),
            "remediation": [
                "Replace curl|sh with a signed package install (apt, npm, pip with hashes).",
                "If you must bootstrap, fetch to a file, verify a SHA-256 against a known-good value, then execute.",
            ],
            "_llm_assist": False,
        }
    return None


def scan_sources(config: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict):
        return findings
    for server_name, server in servers.items():
        if not isinstance(server, dict):
            continue
        for kind, value in _extract_origins(server_name, server):
            finding = _check_origin(server_name, kind, value, server)
            if finding:
                findings.append(finding)
    return findings

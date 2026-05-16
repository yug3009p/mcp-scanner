"""MCP-Scanner: AI Agent Security Auditor.

Modular static + LLM-assisted security scanners for Model Context Protocol
(MCP) server configurations and AI agent tool definitions.
"""

from scanner.auth_scanner import scan_authentication
from scanner.cvss import build_cvss, severity_from_score
from scanner.permissions import scan_permissions
from scanner.prompt_injection import scan_prompt_injection
from scanner.secrets_scanner import scan_secrets
from scanner.shadowing import scan_shadowing
from scanner.source_verification import scan_sources
from scanner.tool_poisoning import scan_tool_poisoning

__all__ = [
    "build_cvss",
    "scan_authentication",
    "scan_permissions",
    "scan_prompt_injection",
    "scan_secrets",
    "scan_shadowing",
    "scan_sources",
    "scan_tool_poisoning",
    "severity_from_score",
]

__version__ = "1.0.0"

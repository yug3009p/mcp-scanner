"""CVSS 3.1 base score helper.

A minimal, dependency-free implementation of the CVSS 3.1 base metric group
sufficient for producing vendor-grade severity bands and vector strings for
each finding. Implements the official CVSS 3.1 specification weights and the
exploitability/impact sub-formulae from FIRST.org.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Literal

# ── CVSS 3.1 metric weights (FIRST.org reference) ──────────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

AttackVector = Literal["N", "A", "L", "P"]
AttackComplexity = Literal["L", "H"]
PrivilegesRequired = Literal["N", "L", "H"]
UserInteraction = Literal["N", "R"]
Scope = Literal["U", "C"]
Impact = Literal["H", "L", "N"]


@dataclass(frozen=True)
class CVSSResult:
    base_score: float
    severity: str
    vector: str
    exploitability: float
    impact: float
    metrics: dict = field(default_factory=dict)


def _round_up(value: float) -> float:
    """Round up to one decimal place per CVSS 3.1 spec (Appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def severity_from_score(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def build_cvss(
    av: AttackVector = "N",
    ac: AttackComplexity = "L",
    pr: PrivilegesRequired = "N",
    ui: UserInteraction = "N",
    scope: Scope = "U",
    c: Impact = "N",
    i: Impact = "N",
    a: Impact = "N",
) -> CVSSResult:
    """Compute a CVSS 3.1 base score from the standard metric letters.

    Args:
        av: Attack Vector (Network/Adjacent/Local/Physical)
        ac: Attack Complexity (Low/High)
        pr: Privileges Required (None/Low/High)
        ui: User Interaction (None/Required)
        scope: Scope (Unchanged/Changed)
        c: Confidentiality impact (High/Low/None)
        i: Integrity impact
        a: Availability impact

    Returns:
        CVSSResult with base_score, severity band, and CVSS vector string.
    """
    av_w = _AV[av]
    ac_w = _AC[ac]
    pr_w = _PR_C[pr] if scope == "C" else _PR_U[pr]
    ui_w = _UI[ui]
    c_w, i_w, a_w = _CIA[c], _CIA[i], _CIA[a]

    iss = 1 - ((1 - c_w) * (1 - i_w) * (1 - a_w))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av_w * ac_w * pr_w * ui_w

    if impact <= 0:
        base = 0.0
    elif scope == "U":
        base = _round_up(min(impact + exploitability, 10))
    else:
        base = _round_up(min(1.08 * (impact + exploitability), 10))

    vector = (
        f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}"
        f"/C:{c}/I:{i}/A:{a}"
    )

    return CVSSResult(
        base_score=base,
        severity=severity_from_score(base),
        vector=vector,
        exploitability=round(exploitability, 2),
        impact=round(max(impact, 0.0), 2),
        metrics={
            "AV": av, "AC": ac, "PR": pr, "UI": ui,
            "S": scope, "C": c, "I": i, "A": a,
        },
    )


# ── Pre-built CVSS profiles for the common MCP attack patterns ─────────────────

PROFILES = {
    # RCE-grade: network, no auth, full CIA impact
    "remote_code_execution": dict(av="N", ac="L", pr="N", ui="N", scope="C",
                                   c="H", i="H", a="H"),
    # Filesystem over-permission: local, low complexity, high CI impact
    "broad_filesystem": dict(av="L", ac="L", pr="L", ui="N", scope="U",
                              c="H", i="H", a="L"),
    # Hardcoded credentials: network reachable, no user interaction
    "hardcoded_secret": dict(av="N", ac="L", pr="N", ui="N", scope="C",
                              c="H", i="H", a="N"),
    # Prompt injection via untrusted input
    "prompt_injection": dict(av="N", ac="L", pr="N", ui="R", scope="C",
                              c="H", i="H", a="N"),
    # Tool poisoning — instructions hidden in tool description
    "tool_poisoning": dict(av="N", ac="L", pr="N", ui="N", scope="C",
                            c="H", i="H", a="N"),
    # Cross-tool shadowing — name collision steers calls
    "tool_shadowing": dict(av="N", ac="L", pr="L", ui="R", scope="C",
                            c="L", i="H", a="N"),
    # Missing authentication on dangerous endpoints
    "missing_auth": dict(av="N", ac="L", pr="N", ui="N", scope="U",
                          c="H", i="H", a="L"),
    # Unverified / unsigned MCP source
    "unverified_source": dict(av="N", ac="H", pr="N", ui="R", scope="C",
                               c="H", i="H", a="H"),
    # Network egress too wide (SSRF surface)
    "broad_network": dict(av="N", ac="L", pr="L", ui="N", scope="C",
                           c="H", i="L", a="L"),
    # Informational / hygiene
    "low_hygiene": dict(av="N", ac="H", pr="L", ui="R", scope="U",
                         c="L", i="N", a="N"),
}


def cvss_for_profile(profile: str) -> CVSSResult:
    """Look up a pre-built CVSS profile by name. Falls back to low-hygiene."""
    return build_cvss(**PROFILES.get(profile, PROFILES["low_hygiene"]))

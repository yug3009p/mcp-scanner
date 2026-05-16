"""MCP-Scanner — AI Agent Security Auditor.

Streamlit application that audits Model Context Protocol (MCP) server
configurations and AI-agent tool definitions against seven attack
categories drawn from OWASP LLM Top 10 (2025) and OWASP Agentic Top 10
(2025). Static scanners are deterministic; Groq Llama 3.3 70B optionally
enriches findings with natural-language attack scenarios and remediation.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st
from dotenv import load_dotenv

try:
    from groq import (
        APIConnectionError,
        APIStatusError,
        AuthenticationError,
        Groq,
    )
except ImportError:  # pragma: no cover
    Groq = None  # type: ignore
    AuthenticationError = APIConnectionError = APIStatusError = Exception  # type: ignore

from scanner import (
    scan_authentication,
    scan_permissions,
    scan_prompt_injection,
    scan_secrets,
    scan_shadowing,
    scan_sources,
    scan_tool_poisoning,
    severity_from_score,
)

load_dotenv()

BASE_DIR = Path(__file__).parent.resolve()
SAMPLES_DIR = BASE_DIR / "samples"
REPORTS_DIR = BASE_DIR / "reports"
HISTORY_FILE = REPORTS_DIR / "_history.json"
REPORTS_DIR.mkdir(exist_ok=True)


# ── CONSTANTS ─────────────────────────────────────────────────────────────────

GROQ_MODEL = "llama-3.3-70b-versatile"

SCANNERS: dict[str, dict[str, Any]] = {
    "prompt_injection": {
        "label": "Prompt Injection Surfaces",
        "icon": "💉",
        "fn": scan_prompt_injection,
        "description": "Finds untrusted input flowing into LLM context.",
    },
    "tool_poisoning": {
        "label": "Tool Poisoning",
        "icon": "☠",
        "fn": scan_tool_poisoning,
        "description": "Detects malicious / hidden directives in tool descriptions.",
    },
    "permissions": {
        "label": "Overly Broad Permissions",
        "icon": "🔓",
        "fn": scan_permissions,
        "description": "Flags filesystem / network / exec scopes that are too wide.",
    },
    "secrets": {
        "label": "Hardcoded Secrets",
        "icon": "🔑",
        "fn": scan_secrets,
        "description": "Regex + entropy scan for API keys, tokens, passwords.",
    },
    "sources": {
        "label": "Unverified Server Sources",
        "icon": "📦",
        "fn": scan_sources,
        "description": "Flags unsigned, unpinned, or untrusted-origin MCP packages.",
    },
    "shadowing": {
        "label": "Cross-Tool Shadowing",
        "icon": "🪞",
        "fn": scan_shadowing,
        "description": "Detects tools with conflicting / overlapping names.",
    },
    "auth": {
        "label": "Missing Authentication",
        "icon": "🛂",
        "fn": scan_authentication,
        "description": "Flags MCP endpoints with no auth or scope controls.",
    },
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_WEIGHTS = {"Critical": 40, "High": 20, "Medium": 8, "Low": 3}
SEVERITY_CONFIG = {
    "Critical": {"color": "#EF4444", "glow": "rgba(239,68,68,0.55)",  "cls": "severity-critical"},
    "High":     {"color": "#F97316", "glow": "rgba(249,115,22,0.45)", "cls": "severity-high"},
    "Medium":   {"color": "#FACC15", "glow": "rgba(250,204,21,0.35)", "cls": "severity-medium"},
    "Low":      {"color": "#10B981", "glow": "rgba(16,185,129,0.35)", "cls": "severity-low"},
}

LLM_SYSTEM_PROMPT = """You are a senior AI security researcher with deep expertise in:
- OWASP LLM Top 10 (2025): LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM06 Excessive Agency, LLM07 System Prompt Leakage
- OWASP Agentic AI Top 10 (2025): memory poisoning, tool misuse, privilege compromise, supply-chain agent risks
- Model Context Protocol (MCP) attack patterns documented by Invariant Labs (April 2025), and the EchoLeak / GitHub-Copilot incidents of mid-2025
- Tool-poisoning, cross-tool shadowing, and prompt-injection-to-exploit chains
- CVSS 3.1 base scoring

You will receive a parsed MCP configuration plus a list of pre-computed static findings. Your job is to:
1. Review the input for *additional* tool-poisoning evidence missed by regex (semantic check)
2. For each existing finding, produce a tightened single-paragraph attack scenario (≤80 words, plain English, concrete)
3. Suggest one extra remediation step beyond the static recommendations where useful

Respond ONLY with valid JSON, no markdown, no code fences, in this exact schema:

{
  "extra_findings": [
    {
      "title": "...",
      "severity": "Critical|High|Medium|Low",
      "category": "Tool Poisoning",
      "component": "path.to.field",
      "scenario": "...",
      "remediation": ["step 1", "step 2"]
    }
  ],
  "enriched": [
    {"id": "MCP-...", "scenario": "tightened scenario", "extra_remediation": "one extra step"}
  ]
}

Rules: severity must be one of Critical/High/Medium/Low. If you find nothing extra, return empty arrays. Be precise and concrete. Never invent CVE IDs."""


# ── CONFIG LOADING / PARSING ──────────────────────────────────────────────────

def load_samples() -> dict[str, str]:
    samples: dict[str, str] = {}
    if not SAMPLES_DIR.exists():
        return samples
    for path in sorted(SAMPLES_DIR.glob("*.json")):
        name = path.stem.replace("_", " ").title()
        samples[name] = path.read_text(encoding="utf-8")
    return samples


def parse_config(text: str) -> tuple[dict | None, str | None]:
    if not text or not text.strip():
        return None, "Configuration is empty."
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON at line {e.lineno}, col {e.colno}: {e.msg}"
    if not isinstance(parsed, dict):
        return None, "Top-level config must be a JSON object."
    return parsed, None


# ── SCANNING + LLM ENRICHMENT ─────────────────────────────────────────────────

def run_static_scanners(
    config: dict,
    enabled: dict[str, bool],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    scanner_map = {
        "prompt_injection": scan_prompt_injection,
        "tool_poisoning":   scan_tool_poisoning,
        "permissions":      scan_permissions,
        "secrets":          scan_secrets,
        "sources":          scan_sources,
        "shadowing":        scan_shadowing,
        "auth":             scan_authentication,
    }
    for key, fn in scanner_map.items():
        if enabled.get(key, True):
            try:
                findings.extend(fn(config))
            except Exception as exc:  # pragma: no cover - defensive
                findings.append({
                    "id": f"MCP-ERR-{key.upper()}",
                    "scanner": key,
                    "category": "Scanner Error",
                    "title": f"Scanner `{key}` raised an exception",
                    "severity": "Low",
                    "cvss_score": 0.0,
                    "cvss_vector": "n/a",
                    "owasp_llm": "—",
                    "owasp_agentic": "—",
                    "cwe": "—",
                    "component": "scanner",
                    "evidence": str(exc),
                    "scenario": "An internal scanner crashed; manual review required.",
                    "remediation": ["File an issue with the offending config (sanitised)."],
                    "_llm_assist": False,
                })
    return findings


def enrich_with_llm(
    config: dict,
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Optionally enrich + augment findings with Groq Llama 3.3 70B.

    Returns (updated_findings, warnings). On any failure the original
    findings are returned unchanged and a warning is recorded.
    """
    warnings: list[str] = []
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        warnings.append("GROQ_API_KEY not set — static scanners only (no LLM enrichment).")
        return findings, warnings
    if Groq is None:
        warnings.append("Groq SDK not installed — static scanners only.")
        return findings, warnings

    try:
        client = Groq(api_key=api_key)
        compact_findings = [
            {k: v for k, v in f.items() if k in {"id", "title", "severity", "category", "component", "evidence"}}
            for f in findings
        ]
        user_msg = (
            "MCP CONFIGURATION (parsed JSON):\n"
            f"{json.dumps(config, indent=2)[:6000]}\n\n"
            "STATIC FINDINGS:\n"
            f"{json.dumps(compact_findings, indent=2)[:4000]}\n\n"
            "Respond with the JSON schema only."
        )
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            max_tokens=2400,
            messages=[
                {"role": "system", "content": LLM_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.splitlines()[1:-1])
        data = json.loads(raw)

        # Enrich existing
        by_id = {f["id"]: f for f in findings}
        for item in data.get("enriched", []) or []:
            fid = item.get("id")
            if fid in by_id:
                if item.get("scenario"):
                    by_id[fid]["scenario"] = item["scenario"]
                if item.get("extra_remediation"):
                    by_id[fid].setdefault("remediation", []).append(
                        item["extra_remediation"]
                    )
                by_id[fid]["_llm_assist"] = True

        # Append extras
        for item in data.get("extra_findings", []) or []:
            sev = item.get("severity", "Medium")
            score_map = {"Critical": 9.4, "High": 7.8, "Medium": 5.5, "Low": 3.0}
            findings.append({
                "id": f"MCP-LLM-{abs(hash(item.get('title', ''))) % 10000:04d}",
                "scanner": "llm_review",
                "category": item.get("category", "Tool Poisoning"),
                "title": item.get("title", "LLM-identified concern"),
                "severity": sev if sev in SEVERITY_ORDER else "Medium",
                "cvss_score": score_map.get(sev, 5.5),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                "owasp_llm": "LLM01:2025 — Prompt Injection",
                "owasp_agentic": "AAI04:2025 — Tool Misuse",
                "cwe": "CWE-77",
                "component": item.get("component", "—"),
                "evidence": "LLM semantic review",
                "scenario": item.get("scenario", ""),
                "remediation": item.get("remediation", []) or [],
                "_llm_assist": True,
            })
    except AuthenticationError:
        warnings.append("Invalid GROQ_API_KEY — static scanners only (no LLM enrichment).")
    except APIConnectionError:
        warnings.append("Could not reach Groq API — static scanners only (no LLM enrichment).")
    except APIStatusError as exc:
        warnings.append(f"Groq API {exc.status_code}: {exc.message} — falling back to static scanners.")
    except (json.JSONDecodeError, KeyError):
        warnings.append("LLM returned malformed JSON — static results returned without enrichment.")
    except Exception as exc:  # pragma: no cover - defensive
        warnings.append(f"LLM enrichment failed: {exc} — static results returned.")
    return findings, warnings


def calculate_risk_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    if not findings:
        return 0, "No risk detected"
    total = sum(SEVERITY_WEIGHTS.get(f.get("severity", "Low"), 0) for f in findings)
    # Cap at 100; one Critical alone is 40, so the 100 ceiling is 2-3 Criticals.
    score = min(100, total)
    if score == 0:
        label = "No risk detected"
    elif score < 20:
        label = "Low risk"
    elif score < 50:
        label = "Moderate risk"
    elif score < 75:
        label = "High risk"
    else:
        label = "Critical risk — do not deploy"
    return score, label


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", "Low"), 99),
            -float(f.get("cvss_score", 0)),
            f.get("scanner", ""),
        ),
    )


# ── HISTORY ───────────────────────────────────────────────────────────────────

def load_history() -> list[dict]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
    return []


def save_history(history: list[dict]) -> None:
    try:
        HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")
    except OSError:
        pass


def append_history(input_text: str, findings: list[dict], score: int) -> None:
    history = load_history()
    history.append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "input_preview": input_text[:140],
        "findings_count": len(findings),
        "risk_score": score,
        "by_severity": {
            sev: sum(1 for f in findings if f.get("severity") == sev)
            for sev in SEVERITY_ORDER
        },
    })
    save_history(history[-50:])


def header_stats(history: list[dict]) -> dict:
    today = datetime.now().date().isoformat()
    today_entries = [h for h in history if h.get("timestamp", "").startswith(today)]
    crit = sum(h.get("by_severity", {}).get("Critical", 0) for h in today_entries)
    if today_entries:
        avg_score = round(
            sum(h.get("risk_score", 0) for h in today_entries) / len(today_entries)
        )
    else:
        avg_score = 0
    return {
        "scanned_today": len(today_entries),
        "critical_today": crit,
        "avg_risk_today": avg_score,
    }


# ── EXPORT ────────────────────────────────────────────────────────────────────

def export_json(findings: list[dict], score: int, label: str, config: dict | None) -> str:
    return json.dumps(
        {
            "tool": "MCP-Scanner",
            "version": "1.0.0",
            "generated": datetime.now().isoformat(),
            "risk_score": score,
            "risk_label": label,
            "findings_count": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f.get("severity") == sev)
                for sev in SEVERITY_ORDER
            },
            "findings": findings,
            "config_name": (config or {}).get("name", "—"),
        },
        indent=2,
    )


def export_markdown(findings: list[dict], score: int, label: str, config: dict | None) -> str:
    cfg_name = (config or {}).get("name", "—")
    by_sev = {
        sev: sum(1 for f in findings if f.get("severity") == sev)
        for sev in SEVERITY_ORDER
    }
    lines = [
        f"# MCP-Scanner Audit Report",
        "",
        f"- **Configuration**: `{cfg_name}`",
        f"- **Generated**: {datetime.now().isoformat(timespec='seconds')}",
        f"- **Risk Score**: {score}/100 — {label}",
        f"- **Findings**: {len(findings)} "
        f"(Critical: {by_sev['Critical']}, High: {by_sev['High']}, "
        f"Medium: {by_sev['Medium']}, Low: {by_sev['Low']})",
        "",
        "---",
        "",
    ]
    for f in findings:
        lines.extend([
            f"## [{f.get('severity')}] {f.get('title')}",
            "",
            f"- **ID**: `{f.get('id')}`",
            f"- **Category**: {f.get('category')}",
            f"- **CVSS 3.1**: {f.get('cvss_score')} ({f.get('cvss_vector')})",
            f"- **OWASP LLM Top 10**: {f.get('owasp_llm')}",
            f"- **OWASP Agentic Top 10**: {f.get('owasp_agentic')}",
            f"- **CWE**: {f.get('cwe')}",
            f"- **Component**: `{f.get('component')}`",
            f"- **Evidence**: {f.get('evidence')}",
            "",
            f"**Attack scenario** — {f.get('scenario')}",
            "",
            "**Remediation**:",
        ])
        for step in f.get("remediation", []) or []:
            lines.append(f"- {step}")
        lines.extend(["", "---", ""])
    return "\n".join(lines)


def export_html(findings: list[dict], score: int, label: str, config: dict | None) -> str:
    cfg_name = (config or {}).get("name", "—")
    by_sev = {
        sev: sum(1 for f in findings if f.get("severity") == sev)
        for sev in SEVERITY_ORDER
    }
    css = """
body{background:#0A0E1A;color:#E5E7EB;font-family:Inter,system-ui,sans-serif;
margin:0;padding:2rem;}h1,h2{color:#00D9FF;}.card{background:#131829;
border:1px solid #1F2937;border-radius:10px;padding:1.25rem;margin-bottom:1rem;}
.sev{display:inline-block;padding:.3rem .8rem;border-radius:999px;
font-weight:700;letter-spacing:.1em;text-transform:uppercase;font-size:.7rem;}
.Critical{background:rgba(239,68,68,.15);color:#EF4444;border:1px solid #EF4444;}
.High{background:rgba(249,115,22,.15);color:#F97316;border:1px solid #F97316;}
.Medium{background:rgba(250,204,21,.12);color:#FACC15;border:1px solid #FACC15;}
.Low{background:rgba(16,185,129,.12);color:#10B981;border:1px solid #10B981;}
.chip{display:inline-block;background:rgba(124,58,237,.18);color:#A78BFA;
border:1px solid rgba(124,58,237,.4);border-radius:6px;padding:.15rem .55rem;
font-size:.7rem;margin-right:.3rem;}code{background:#0A0E1A;padding:.1rem .3rem;
border-radius:4px;font-family:JetBrains Mono,monospace;}.score{font-size:3rem;
font-weight:800;color:#00D9FF;}.scenario{color:#D1D5DB;line-height:1.6;
margin-top:.6rem;}.remediation li{color:#9CA3AF;margin-bottom:.25rem;}
"""
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>MCP-Scanner Audit Report</title>",
        f"<style>{css}</style></head><body>",
        f"<h1>🛡 MCP-Scanner — Audit Report</h1>",
        "<div class='card'>",
        f"<p><strong>Configuration:</strong> <code>{cfg_name}</code></p>",
        f"<p><strong>Generated:</strong> {datetime.now().isoformat(timespec='seconds')}</p>",
        f"<p class='score'>{score}/100</p>",
        f"<p><strong>{label}</strong></p>",
        f"<p>Findings: {len(findings)} — "
        f"Critical {by_sev['Critical']} · High {by_sev['High']} · "
        f"Medium {by_sev['Medium']} · Low {by_sev['Low']}</p>",
        "</div>",
    ]
    for f in findings:
        sev = f.get("severity", "Low")
        remediation_items = "".join(
            f"<li>{step}</li>" for step in f.get("remediation", []) or []
        )
        parts.append(
            f"<div class='card'>"
            f"<h2>{f.get('title')}</h2>"
            f"<p><span class='sev {sev}'>{sev}</span> "
            f"<span class='chip'>{f.get('owasp_llm', '—')}</span> "
            f"<span class='chip'>{f.get('owasp_agentic', '—')}</span> "
            f"<span class='chip'>{f.get('cwe', '—')}</span></p>"
            f"<p><code>{f.get('component')}</code> · CVSS {f.get('cvss_score')} "
            f"(<code>{f.get('cvss_vector')}</code>)</p>"
            f"<p><strong>Evidence:</strong> {f.get('evidence')}</p>"
            f"<p class='scenario'>{f.get('scenario')}</p>"
            f"<p><strong>Remediation:</strong></p>"
            f"<ul class='remediation'>{remediation_items}</ul>"
            f"</div>"
        )
    parts.append("</body></html>")
    return "".join(parts)


def save_report_to_disk(json_text: str) -> Path:
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    path = REPORTS_DIR / f"report_{ts}.json"
    path.write_text(json_text, encoding="utf-8")
    return path


# ── CSS ───────────────────────────────────────────────────────────────────────

def inject_css() -> None:
    st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', system-ui, -apple-system, sans-serif !important;
    color: #E5E7EB !important;
}
.stApp {
    background-color: #0A0E1A !important;
    background-image:
      radial-gradient(circle at 1px 1px, rgba(0,217,255,0.06) 1px, transparent 0),
      linear-gradient(180deg, rgba(124,58,237,0.04) 0%, transparent 50%);
    background-size: 28px 28px, auto;
    background-attachment: fixed;
}
#MainMenu, footer { visibility: hidden; }
header[data-testid="stHeader"] { display: none !important; }
.block-container {
    padding-top: 0.75rem !important;
    padding-bottom: 0.5rem !important;
    max-width: 100% !important;
    padding-left: 1.25rem !important;
    padding-right: 1.25rem !important;
}

/* ── SIDEBAR ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0D1120 0%, #0A0E1A 100%) !important;
    border-right: 1px solid #1F2937 !important;
    min-width: 280px !important;
    max-width: 310px !important;
}
[data-testid="stSidebar"] > div:first-child { padding-top: 0.5rem; }
[data-testid="stSidebar"] .block-container { padding: 0.5rem 1rem !important; }

/* ── HEADER ── */
.mcp-header {
    background: linear-gradient(90deg, #0D1120 0%, #131829 40%, #0D1120 100%);
    border: 1px solid #1F2937;
    border-radius: 10px;
    padding: 0.85rem 1.4rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
    position: relative;
    overflow: hidden;
}
.mcp-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent 0%, #00D9FF 40%, #7C3AED 70%, transparent 100%);
}
.mcp-header::after {
    content: '';
    position: absolute;
    top: 0; right: 0; bottom: 0;
    width: 30%;
    background: radial-gradient(ellipse at right, rgba(124,58,237,0.06) 0%, transparent 70%);
    pointer-events: none;
}
.mcp-brand { display: flex; align-items: center; gap: 0.85rem; }
.mcp-brand-icon {
    font-size: 1.9rem;
    filter: drop-shadow(0 0 10px rgba(0,217,255,0.7));
    animation: icon-pulse 3s ease-in-out infinite;
}
@keyframes icon-pulse {
    0%, 100% { filter: drop-shadow(0 0 8px rgba(0,217,255,0.6)); }
    50%       { filter: drop-shadow(0 0 18px rgba(0,217,255,0.9)); }
}
.mcp-brand-name {
    font-size: 1.35rem;
    font-weight: 700;
    color: #E5E7EB;
    letter-spacing: -0.02em;
    line-height: 1.1;
}
.mcp-brand-tagline {
    font-size: 0.62rem;
    color: #00D9FF;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    font-weight: 500;
}
.mcp-live-dot {
    display: inline-block;
    width: 6px; height: 6px;
    background: #10B981;
    border-radius: 50%;
    margin-right: 0.3rem;
    animation: live-blink 1.8s ease-in-out infinite;
}
@keyframes live-blink {
    0%, 100% { opacity: 1; box-shadow: 0 0 4px #10B981; }
    50%       { opacity: 0.4; box-shadow: none; }
}
.mcp-stats { display: flex; gap: 1.75rem; align-items: center; }
.mcp-stat { text-align: center; }
.mcp-stat-value { font-size: 1.05rem; font-weight: 700; color: #00D9FF; display: block; line-height: 1.1; }
.mcp-stat-label { font-size: 0.6rem; color: #6B7280; text-transform: uppercase; letter-spacing: 0.12em; }
.mcp-stat-divider { width: 1px; height: 2rem; background: #1F2937; }

/* ── CARDS ── */
.mcp-card {
    background: rgba(19,24,41,0.9);
    border: 1px solid #1F2937;
    border-radius: 10px;
    padding: 1.1rem 1.2rem;
    margin-bottom: 0.85rem;
    backdrop-filter: blur(10px);
    transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
}
.mcp-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 24px rgba(0,217,255,0.07);
    border-color: rgba(0,217,255,0.2);
}
.mcp-card-title {
    font-size: 0.6rem;
    color: #6B7280;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    font-weight: 600;
    margin-bottom: 0.7rem;
    display: flex;
    align-items: center;
    gap: 0.4rem;
}
.mcp-card-title::after {
    content: '';
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, #1F2937, transparent);
}

/* ── FINDING CARDS ── */
.finding-card {
    background: rgba(19,24,41,0.92);
    border: 1px solid #1F2937;
    border-left-width: 3px;
    border-radius: 10px;
    padding: 1rem 1.15rem;
    margin-bottom: 0.85rem;
    transition: all 0.25s ease;
    animation: fadeSlideUp 0.35s ease forwards;
}
.finding-card.Critical { border-left-color: #EF4444; box-shadow: 0 0 16px rgba(239,68,68,0.18); }
.finding-card.High     { border-left-color: #F97316; box-shadow: 0 0 12px rgba(249,115,22,0.15); }
.finding-card.Medium   { border-left-color: #FACC15; }
.finding-card.Low      { border-left-color: #10B981; }
.finding-card:hover { border-color: rgba(0,217,255,0.3); transform: translateX(2px); }
.finding-head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.5rem;
    flex-wrap: wrap;
}
.finding-id {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #4B5563;
    letter-spacing: 0.05em;
}
.finding-title {
    font-size: 0.96rem;
    color: #E5E7EB;
    font-weight: 600;
    margin: 0.1rem 0 0.4rem;
    line-height: 1.35;
}
.finding-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
    margin-bottom: 0.65rem;
}
.finding-component {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #67E8F9;
    background: rgba(0,217,255,0.06);
    border: 1px solid rgba(0,217,255,0.15);
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    word-break: break-all;
}
.finding-cvss {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #9CA3AF;
    background: rgba(31,41,55,0.6);
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
}
.finding-scenario {
    font-size: 0.82rem;
    color: #D1D5DB;
    line-height: 1.6;
    margin: 0.55rem 0 0.7rem;
    padding: 0.55rem 0.75rem;
    background: rgba(10,14,26,0.5);
    border-left: 2px solid rgba(0,217,255,0.25);
    border-radius: 4px;
}
.finding-evidence {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    color: #6B7280;
    margin-bottom: 0.5rem;
    word-break: break-all;
}
.finding-remediation-title {
    font-size: 0.6rem;
    color: #6B7280;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    font-weight: 600;
    margin-bottom: 0.35rem;
}
.finding-rem-item {
    display: flex;
    gap: 0.55rem;
    padding: 0.3rem 0;
    border-bottom: 1px solid rgba(31,41,55,0.5);
    font-size: 0.78rem;
    color: #D1D5DB;
    line-height: 1.5;
}
.finding-rem-item:last-child { border-bottom: none; }
.finding-rem-num {
    flex-shrink: 0;
    width: 18px; height: 18px;
    background: rgba(124,58,237,0.18);
    border: 1px solid rgba(124,58,237,0.4);
    border-radius: 4px;
    font-size: 0.6rem;
    font-weight: 700;
    color: #A78BFA;
    display: flex; align-items: center; justify-content: center;
}
.llm-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.55rem;
    color: #7C3AED;
    background: rgba(124,58,237,0.1);
    border: 1px solid rgba(124,58,237,0.3);
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 600;
}

/* ── SEVERITY BADGES ── */
.severity-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.3rem 0.85rem;
    border-radius: 999px;
    font-weight: 700;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    border: 1.5px solid;
}
.severity-critical {
    color: #EF4444;
    background: rgba(239,68,68,0.12);
    border-color: #EF4444;
    animation: pulse-red 2s ease-in-out infinite;
}
@keyframes pulse-red {
    0%, 100% { box-shadow: 0 0 8px rgba(239,68,68,0.3); }
    50%       { box-shadow: 0 0 18px rgba(239,68,68,0.65), 0 0 28px rgba(239,68,68,0.2); }
}
.severity-high {
    color: #F97316;
    background: rgba(249,115,22,0.12);
    border-color: #F97316;
    box-shadow: 0 0 10px rgba(249,115,22,0.3);
}
.severity-medium {
    color: #FACC15;
    background: rgba(250,204,21,0.1);
    border-color: #FACC15;
    box-shadow: 0 0 8px rgba(250,204,21,0.2);
}
.severity-low {
    color: #10B981;
    background: rgba(16,185,129,0.1);
    border-color: #10B981;
    box-shadow: 0 0 8px rgba(16,185,129,0.2);
}

/* ── OWASP CHIPS ── */
.owasp-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    background: rgba(124,58,237,0.14);
    border: 1px solid rgba(124,58,237,0.35);
    color: #C4B5FD;
    padding: 0.18rem 0.5rem;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 600;
    cursor: default;
}
.cwe-chip {
    background: rgba(0,217,255,0.08);
    border: 1px solid rgba(0,217,255,0.25);
    color: #67E8F9;
    padding: 0.18rem 0.5rem;
    border-radius: 4px;
    font-size: 0.62rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
}

/* ── RISK SCORE METER ── */
.risk-meter-wrap {
    background: rgba(13,17,32,0.95);
    border: 1px solid #1F2937;
    border-radius: 10px;
    padding: 1.1rem 1.25rem;
    margin-bottom: 0.85rem;
    position: relative;
    overflow: hidden;
}
.risk-meter-head {
    display: flex; justify-content: space-between; align-items: baseline;
    margin-bottom: 0.6rem;
}
.risk-score-num {
    font-size: 2.1rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    color: #00D9FF;
    line-height: 1;
}
.risk-score-out {
    color: #4B5563;
    font-size: 0.85rem;
    font-family: 'JetBrains Mono', monospace;
}
.risk-score-label {
    font-size: 0.65rem;
    color: #6B7280;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    font-weight: 600;
}
.risk-bar {
    height: 10px;
    background: #0A0E1A;
    border-radius: 5px;
    overflow: hidden;
    position: relative;
    border: 1px solid #1F2937;
}
.risk-bar-fill {
    height: 100%;
    border-radius: 5px;
    background: linear-gradient(90deg, #10B981 0%, #FACC15 35%, #F97316 65%, #EF4444 100%);
    transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}
.risk-bar-marker {
    position: absolute;
    top: -3px;
    width: 2px;
    height: 16px;
    background: #E5E7EB;
    box-shadow: 0 0 6px #00D9FF;
}
.risk-tag {
    display: inline-block;
    margin-top: 0.7rem;
    font-size: 0.75rem;
    font-weight: 600;
    color: #E5E7EB;
}

/* ── BUTTONS ── */
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #00D9FF 0%, #0EA5E9 45%, #7C3AED 100%) !important;
    color: #050810 !important;
    font-weight: 700 !important;
    font-size: 0.85rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.18em !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 0.75rem 1.5rem !important;
    box-shadow: 0 0 20px rgba(0,217,255,0.28), 0 4px 12px rgba(0,0,0,0.3) !important;
    transition: all 0.25s ease !important;
    width: 100% !important;
}
.stButton > button[kind="primary"]:hover:not(:disabled) {
    transform: scale(1.02) !important;
    box-shadow: 0 0 36px rgba(0,217,255,0.55), 0 6px 20px rgba(0,0,0,0.4) !important;
}
.stButton > button[kind="primary"]:disabled {
    opacity: 0.3 !important;
    cursor: not-allowed !important;
    box-shadow: none !important;
}
.stButton > button[kind="secondary"] {
    background: rgba(19,24,41,0.7) !important;
    border: 1px solid #1F2937 !important;
    color: #9CA3AF !important;
    font-size: 0.72rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.1em !important;
    padding: 0.5rem 0.7rem !important;
    transition: all 0.2s ease !important;
}
.stButton > button[kind="secondary"]:hover {
    border-color: rgba(0,217,255,0.4) !important;
    color: #E5E7EB !important;
}

/* sidebar buttons */
[data-testid="stSidebar"] .stButton > button {
    background: rgba(19,24,41,0.7) !important;
    border: 1px solid #1F2937 !important;
    border-radius: 6px !important;
    color: #9CA3AF !important;
    font-size: 0.7rem !important;
    padding: 0.4rem 0.6rem !important;
    text-align: left !important;
    width: 100% !important;
    transition: all 0.2s ease !important;
    margin-bottom: 0.22rem !important;
    white-space: normal !important;
    height: auto !important;
    min-height: 2.4rem !important;
    line-height: 1.35 !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
    background: rgba(0,217,255,0.06) !important;
    border-color: rgba(0,217,255,0.35) !important;
    color: #E5E7EB !important;
}

/* download buttons */
.stDownloadButton > button {
    background: rgba(13,17,32,0.9) !important;
    border: 1px solid rgba(0,217,255,0.3) !important;
    color: #67E8F9 !important;
    border-radius: 6px !important;
    font-size: 0.72rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.1em !important;
    padding: 0.5rem 0.75rem !important;
    font-weight: 600 !important;
    transition: all 0.2s ease !important;
    width: 100% !important;
}
.stDownloadButton > button:hover {
    background: rgba(0,217,255,0.08) !important;
    border-color: #00D9FF !important;
    color: #E5E7EB !important;
    box-shadow: 0 0 12px rgba(0,217,255,0.25) !important;
}

/* ── TEXTAREA ── */
.stTextArea textarea {
    background: #080C18 !important;
    color: #86EFAC !important;
    border: 1px solid #1F2937 !important;
    border-radius: 8px !important;
    font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
    font-size: 0.78rem !important;
    line-height: 1.6 !important;
    transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
    caret-color: #00D9FF !important;
}
.stTextArea textarea:focus {
    border-color: rgba(0,217,255,0.5) !important;
    box-shadow: 0 0 0 2px rgba(0,217,255,0.1) !important;
    outline: none !important;
}
.stTextArea textarea::placeholder { color: #2D3748 !important; font-style: italic; }
.stTextArea label, .stSelectbox label, .stCheckbox label {
    color: #6B7280 !important;
    font-size: 0.62rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.15em !important;
    font-weight: 600 !important;
}

/* ── SELECTBOX ── */
.stSelectbox > div > div {
    background: #0D1120 !important;
    border: 1px solid #1F2937 !important;
    color: #E5E7EB !important;
    border-radius: 6px !important;
    font-size: 0.8rem !important;
}

/* ── CHECKBOX ── */
.stCheckbox > label {
    color: #D1D5DB !important;
    font-size: 0.78rem !important;
    text-transform: none !important;
    letter-spacing: normal !important;
    font-weight: 400 !important;
}
.stCheckbox > label > div { color: #D1D5DB !important; }

/* ── EMPTY STATE ── */
.empty-state {
    text-align: center;
    padding: 3.5rem 1rem;
}
.empty-icon { font-size: 2.8rem; display: block; margin-bottom: 0.85rem; opacity: 0.25; }
.empty-label {
    font-size: 0.85rem;
    color: #4B5563;
    letter-spacing: 0.06em;
}

/* ── EXPANDER / DIVIDER ── */
details { background: rgba(13,17,32,0.8) !important; border: 1px solid #1F2937 !important; border-radius: 7px !important; }
details summary { color: #9CA3AF !important; font-size: 0.78rem !important; padding: 0.5rem 0.75rem !important; }
.grad-divider {
    height: 1px;
    background: linear-gradient(90deg, transparent, #1F2937 30%, #1F2937 70%, transparent);
    margin: 0.85rem 0;
    border: none;
}

/* metrics in sidebar */
.metric-row { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; }
.metric-mini {
    flex: 1;
    background: rgba(13,17,32,0.9);
    border: 1px solid #1F2937;
    border-radius: 7px;
    padding: 0.55rem 0.5rem;
    text-align: center;
}
.metric-mini-val { font-size: 1.05rem; font-weight: 700; color: #00D9FF; display: block; }
.metric-mini-lbl { font-size: 0.55rem; color: #6B7280; text-transform: uppercase; letter-spacing: 0.08em; }

/* ── FOOTER ── */
.mcp-footer {
    border-top: 1px solid #1F2937;
    padding: 0.6rem 1.5rem;
    text-align: center;
    color: #4B5563;
    font-size: 0.65rem;
    letter-spacing: 0.04em;
    margin-top: 1rem;
}
.mcp-footer a { color: #6B7280; text-decoration: none; }
.mcp-footer a:hover { color: #00D9FF; }

/* sidebar headers */
[data-testid="stSidebar"] h3 {
    font-size: 0.6rem !important;
    color: #4B5563 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.18em !important;
    font-weight: 600 !important;
    margin: 0.85rem 0 0.5rem 0 !important;
    padding-bottom: 0.35rem !important;
    border-bottom: 1px solid #1F2937 !important;
}

/* ── PRO TIP ── */
.pro-tip {
    background: rgba(0,217,255,0.04);
    border: 1px solid rgba(0,217,255,0.12);
    border-left: 3px solid #00D9FF;
    border-radius: 6px;
    padding: 0.6rem 0.85rem;
    font-size: 0.74rem;
    color: #9CA3AF;
    margin-top: 0.75rem;
    line-height: 1.5;
}

/* animations */
@keyframes fadeSlideUp {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
}
.results-wrap { animation: fadeSlideUp 0.35s ease forwards; }

/* scrollbar */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #0A0E1A; }
::-webkit-scrollbar-thumb { background: #1F2937; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #374151; }

/* typography */
p, .stMarkdown p { color: #D1D5DB !important; font-size: 0.83rem !important; line-height: 1.6; }
h1, h2, h3 { color: #E5E7EB !important; }
small, .stCaption { color: #6B7280 !important; font-size: 0.7rem !important; }

/* toast */
[data-testid="stToast"] {
    background: #131829 !important;
    border: 1px solid #10B981 !important;
    color: #E5E7EB !important;
}

/* error/warning */
.stAlert { background: rgba(239,68,68,0.08) !important; border: 1px solid rgba(239,68,68,0.3) !important; color: #FCA5A5 !important; border-radius: 8px !important; }
</style>
""", unsafe_allow_html=True)


# ── RENDER HELPERS ─────────────────────────────────────────────────────────────

def render_header(stats: dict) -> None:
    risk_color = (
        "#10B981" if stats["avg_risk_today"] < 25
        else "#FACC15" if stats["avg_risk_today"] < 50
        else "#F97316" if stats["avg_risk_today"] < 75
        else "#EF4444"
    )
    st.markdown(f"""
<div class="mcp-header">
  <div class="mcp-brand">
    <span class="mcp-brand-icon">🛡</span>
    <div>
      <div class="mcp-brand-name">MCP-Scanner</div>
      <div class="mcp-brand-tagline">
        <span class="mcp-live-dot"></span>AI Agent Security Auditor
      </div>
    </div>
  </div>
  <div class="mcp-stats">
    <div class="mcp-stat">
      <span class="mcp-stat-value">{stats["scanned_today"]}</span>
      <span class="mcp-stat-label">Configs Scanned Today</span>
    </div>
    <div class="mcp-stat-divider"></div>
    <div class="mcp-stat">
      <span class="mcp-stat-value" style="color:#EF4444;">{stats["critical_today"]}</span>
      <span class="mcp-stat-label">Critical Findings</span>
    </div>
    <div class="mcp-stat-divider"></div>
    <div class="mcp-stat">
      <span class="mcp-stat-value" style="color:{risk_color};">{stats["avg_risk_today"]}/100</span>
      <span class="mcp-stat-label">Avg Risk Today</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


def render_sidebar(samples: dict, history: list[dict]) -> dict[str, bool]:
    """Sidebar: brand, sample picker, history, scanner toggles."""
    st.markdown("""
<div style="text-align:center;padding:0.5rem 0 0.75rem;border-bottom:1px solid #1F2937;margin-bottom:0.75rem;">
  <span style="font-size:1.5rem;filter:drop-shadow(0 0 8px rgba(0,217,255,0.6))">🛡</span>
  <div style="font-size:0.62rem;color:#4B5563;text-transform:uppercase;letter-spacing:0.18em;margin-top:0.2rem;">MCP-Scanner</div>
</div>
""", unsafe_allow_html=True)

    # ── Sample picker ──
    st.markdown("### 📂 Sample Configs")
    sample_names = list(samples.keys())
    if sample_names:
        def _on_pick():
            sel = st.session_state.sample_picker
            if sel and sel != "— Select —":
                st.session_state.config_input = samples[sel]

        st.selectbox(
            "Load a sample",
            options=["— Select —"] + sample_names,
            key="sample_picker",
            on_change=_on_pick,
            label_visibility="collapsed",
        )
    else:
        st.markdown(
            '<div style="color:#4B5563;font-size:0.72rem;padding:0.5rem 0;">No samples found.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="grad-divider"></div>', unsafe_allow_html=True)

    # ── Recent scans ──
    st.markdown("### 👁 Recent Scans")
    recent = history[-5:][::-1] if history else []
    if recent:
        for i, entry in enumerate(recent):
            ts = entry.get("timestamp", "")[:16].replace("T", " ")
            score = entry.get("risk_score", 0)
            count = entry.get("findings_count", 0)
            preview = entry.get("input_preview", "")[:40].replace("\n", " ").strip()
            score_color = (
                "#10B981" if score < 25
                else "#FACC15" if score < 50
                else "#F97316" if score < 75
                else "#EF4444"
            )
            st.markdown(
                f"<div style='font-size:0.68rem;color:{score_color};font-family:JetBrains Mono,monospace;'>"
                f"● {score}/100 · {count} findings · {ts}</div>"
                f"<div style='font-size:0.7rem;color:#6B7280;margin-bottom:0.45rem;padding-left:0.6rem;'>"
                f"{preview}…</div>",
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div style="color:#4B5563;font-size:0.72rem;padding:0.5rem 0;">No scans yet.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="grad-divider"></div>', unsafe_allow_html=True)

    # ── Today's stats ──
    st.markdown("### 🎯 Today's Landscape")
    today = datetime.now().date().isoformat()
    today_h = [h for h in history if h.get("timestamp", "").startswith(today)]
    crit = sum(h.get("by_severity", {}).get("Critical", 0) for h in today_h)
    high = sum(h.get("by_severity", {}).get("High", 0) for h in today_h)
    st.markdown(f"""
<div class="metric-row">
  <div class="metric-mini">
    <span class="metric-mini-val">{len(today_h)}</span>
    <span class="metric-mini-lbl">Scanned</span>
  </div>
  <div class="metric-mini">
    <span class="metric-mini-val" style="color:#EF4444">{crit}</span>
    <span class="metric-mini-lbl">Critical</span>
  </div>
  <div class="metric-mini">
    <span class="metric-mini-val" style="color:#F97316">{high}</span>
    <span class="metric-mini-lbl">High</span>
  </div>
</div>
""", unsafe_allow_html=True)

    st.markdown('<div class="grad-divider"></div>', unsafe_allow_html=True)

    # ── Scanner toggles ──
    st.markdown("### ⚙ Scanner Modules")
    enabled: dict[str, bool] = {}
    for key, meta in SCANNERS.items():
        enabled[key] = st.checkbox(
            f"{meta['icon']}  {meta['label']}",
            value=st.session_state.get(f"sc_{key}", True),
            key=f"sc_{key}",
        )

    st.markdown('<div class="grad-divider"></div>', unsafe_allow_html=True)

    # ── Settings expander ──
    with st.expander("⚙ Engine"):
        api_key_set = bool(os.getenv("GROQ_API_KEY"))
        st.markdown(
            '<div style="font-size:0.72rem;color:#6B7280;line-height:1.6;">'
            f'Model: <span style="color:#67E8F9">{GROQ_MODEL}</span><br>'
            f'Provider: Groq Cloud<br>'
            f'API key: {"✅ configured" if api_key_set else "⚠ not set"}<br>'
            f'Mode: {"Static + LLM enrichment" if api_key_set else "Static scanners only"}<br>'
            f'Standards: OWASP LLM Top 10 (2025), Agentic Top 10 (2025)<br>'
            f'</div>',
            unsafe_allow_html=True,
        )

    return enabled


def render_input_panel(samples: dict) -> tuple[str, bool]:
    st.markdown('<div class="mcp-card-title">📥 MCP CONFIG INPUT</div>',
                unsafe_allow_html=True)

    config_text = st.text_area(
        "MCP config (JSON)",
        height=420,
        placeholder=(
            "Paste your MCP configuration here…\n\n"
            "Accepted formats:\n"
            "  · mcpServers JSON (Claude Desktop, VS Code MCP)\n"
            "  · Tool definitions (OpenAI / Anthropic / function-calling)\n"
            "  · System prompts and agent profiles\n\n"
            "Tip: pick a Sample Config in the sidebar to get started."
        ),
        key="config_input",
        label_visibility="collapsed",
    )

    st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)

    run_clicked = st.button(
        "🔍  RUN AUDIT",
        type="primary",
        use_container_width=True,
        disabled=not (config_text or "").strip(),
    )

    st.markdown("""
<div class="pro-tip">
  💡 <strong style="color:#67E8F9">Pro tip:</strong> The auditor runs seven scanners in parallel and
  enriches findings with semantic analysis from Llama 3.3 70B. No GROQ_API_KEY?
  All static scanners still run — you just won't get the LLM tool-poisoning second pass.
</div>
""", unsafe_allow_html=True)

    return config_text, run_clicked


def render_risk_meter(score: int, label: str, by_sev: dict[str, int]) -> None:
    score_color = (
        "#10B981" if score < 25
        else "#FACC15" if score < 50
        else "#F97316" if score < 75
        else "#EF4444"
    )
    st.markdown(f"""
<div class="risk-meter-wrap">
  <div class="risk-meter-head">
    <div>
      <span class="risk-score-num" style="color:{score_color};">{score}</span>
      <span class="risk-score-out">/100</span>
    </div>
    <div class="risk-score-label">Overall Risk Score</div>
  </div>
  <div class="risk-bar">
    <div class="risk-bar-fill" style="width:{score}%;"></div>
    <div class="risk-bar-marker" style="left:calc({score}% - 1px);"></div>
  </div>
  <div class="risk-tag" style="color:{score_color};">{label}</div>
  <div style="display:flex;gap:0.4rem;margin-top:0.6rem;flex-wrap:wrap;">
    <span class="severity-badge severity-critical" style="font-size:0.6rem;padding:0.2rem 0.6rem;">
      {by_sev.get('Critical', 0)} Critical
    </span>
    <span class="severity-badge severity-high" style="font-size:0.6rem;padding:0.2rem 0.6rem;">
      {by_sev.get('High', 0)} High
    </span>
    <span class="severity-badge severity-medium" style="font-size:0.6rem;padding:0.2rem 0.6rem;">
      {by_sev.get('Medium', 0)} Medium
    </span>
    <span class="severity-badge severity-low" style="font-size:0.6rem;padding:0.2rem 0.6rem;">
      {by_sev.get('Low', 0)} Low
    </span>
  </div>
</div>
""", unsafe_allow_html=True)


def render_finding_card(f: dict) -> None:
    sev = f.get("severity", "Low")
    sev_cls = {"Critical": "severity-critical", "High": "severity-high",
               "Medium": "severity-medium", "Low": "severity-low"}.get(sev, "severity-low")

    title = (f.get("title") or "").replace("<", "&lt;").replace(">", "&gt;")
    evidence = (f.get("evidence") or "").replace("<", "&lt;").replace(">", "&gt;")
    scenario = (f.get("scenario") or "").replace("<", "&lt;").replace(">", "&gt;")
    component = (f.get("component") or "—").replace("<", "&lt;").replace(">", "&gt;")
    cvss_score = f.get("cvss_score", "—")
    cvss_vector = f.get("cvss_vector", "")
    llm_badge = '<span class="llm-badge">✨ LLM</span>' if f.get("_llm_assist") else ""

    head_html = (
        f'<div class="finding-head">'
        f'<span class="severity-badge {sev_cls}">{sev}</span>'
        f'<span class="finding-id">{f.get("id", "")}</span>'
        f'{llm_badge}'
        f'</div>'
    )
    meta_html = (
        f'<div class="finding-meta">'
        f'<span class="owasp-chip">📖 {f.get("owasp_llm", "—")}</span>'
        f'<span class="owasp-chip">🤖 {f.get("owasp_agentic", "—")}</span>'
        f'<span class="cwe-chip">{f.get("cwe", "—")}</span>'
        f'<span class="finding-cvss">CVSS {cvss_score}</span>'
        f'</div>'
    )
    component_html = (
        f'<div style="margin-bottom:0.5rem;">'
        f'<span class="finding-component">{component}</span>'
        f'</div>'
    )
    evidence_html = (
        f'<div class="finding-evidence">📍 Evidence: {evidence}</div>'
        if evidence else ""
    )
    cvss_vector_html = (
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#4B5563;margin-bottom:0.4rem;">'
        f'{cvss_vector}</div>' if cvss_vector else ""
    )

    rem_items = ""
    for i, step in enumerate(f.get("remediation", []) or [], 1):
        step_esc = str(step).replace("<", "&lt;").replace(">", "&gt;")
        rem_items += (
            f'<div class="finding-rem-item">'
            f'<span class="finding-rem-num">{i}</span>'
            f'<span>{step_esc}</span>'
            f'</div>'
        )
    rem_block = (
        f'<div class="finding-remediation-title">🛠 Remediation</div>{rem_items}'
        if rem_items else ""
    )

    st.markdown(
        f'<div class="finding-card {sev}">'
        f'{head_html}'
        f'<div class="finding-title">{title}</div>'
        f'{meta_html}'
        f'{component_html}'
        f'{cvss_vector_html}'
        f'{evidence_html}'
        f'<div class="finding-scenario">🎯 {scenario}</div>'
        f'{rem_block}'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_results_panel() -> None:
    findings: list[dict] = st.session_state.get("findings") or []
    score = st.session_state.get("risk_score", 0)
    label = st.session_state.get("risk_label", "")
    config = st.session_state.get("parsed_config")
    warnings: list[str] = st.session_state.get("warnings") or []

    if not findings and not st.session_state.get("scan_ran"):
        st.markdown('<div class="mcp-card-title">📊 AUDIT RESULTS</div>',
                    unsafe_allow_html=True)
        st.markdown("""
<div class="empty-state">
  <span class="empty-icon">🛡</span>
  <div class="empty-label">Awaiting MCP configuration</div>
  <div style="margin-top:0.8rem;color:#2D3748;font-size:0.7rem;letter-spacing:0.2em;">· · ·</div>
  <div style="margin-top:1.5rem;color:#1F2937;font-size:0.7rem;line-height:1.8;">
    Paste an MCP config in the input panel<br>or pick a sample from the sidebar
  </div>
</div>
""", unsafe_allow_html=True)
        return

    st.markdown('<div class="results-wrap">', unsafe_allow_html=True)
    st.markdown('<div class="mcp-card-title">📊 AUDIT RESULTS</div>',
                unsafe_allow_html=True)

    by_sev = {sev: sum(1 for f in findings if f.get("severity") == sev)
              for sev in SEVERITY_ORDER}
    render_risk_meter(score, label, by_sev)

    for warning in warnings:
        st.warning(warning, icon="⚠")

    if not findings:
        st.markdown("""
<div class="mcp-card" style="border-color:rgba(16,185,129,0.4);
     box-shadow:0 0 16px rgba(16,185,129,0.18);">
  <div class="mcp-card-title">✅ Clean Audit</div>
  <div style="font-size:0.88rem;color:#86EFAC;font-weight:600;">
    All seven scanners passed. This configuration meets the secure baseline.
  </div>
  <div style="font-size:0.78rem;color:#9CA3AF;margin-top:0.5rem;line-height:1.6;">
    Continue to monitor: pin every package version, rotate auth tokens quarterly,
    and re-audit on any config change.
  </div>
</div>
""", unsafe_allow_html=True)
    else:
        for f in findings:
            render_finding_card(f)

    # Export buttons
    if findings or config:
        st.markdown('<div class="mcp-card-title" style="margin-top:0.5rem;">📤 EXPORT REPORT</div>',
                    unsafe_allow_html=True)
        col_j, col_h, col_m = st.columns(3)
        ts = datetime.now().strftime("%Y%m%dT%H%M%S")
        with col_j:
            st.download_button(
                "⬇ JSON",
                data=export_json(findings, score, label, config),
                file_name=f"mcp_audit_{ts}.json",
                mime="application/json",
                use_container_width=True,
            )
        with col_h:
            st.download_button(
                "⬇ HTML",
                data=export_html(findings, score, label, config),
                file_name=f"mcp_audit_{ts}.html",
                mime="text/html",
                use_container_width=True,
            )
        with col_m:
            st.download_button(
                "⬇ Markdown",
                data=export_markdown(findings, score, label, config),
                file_name=f"mcp_audit_{ts}.md",
                mime="text/markdown",
                use_container_width=True,
            )

    st.markdown("</div>", unsafe_allow_html=True)


def render_footer() -> None:
    st.markdown("""
<div class="mcp-footer">
  Powered by Llama 3.3 70B via Groq &nbsp;·&nbsp; Static scanners written in pure Python
  &nbsp;·&nbsp; Aligned to OWASP LLM Top 10 (2025) &amp; OWASP Agentic Top 10 (2025)
  &nbsp;·&nbsp; Built by
  <a href="https://www.linkedin.com/in/yug-patel-b9727226b/" target="_blank">Yug Patel</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/yug3009p" target="_blank">github.com/yug3009p</a>
</div>
""", unsafe_allow_html=True)


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main() -> None:
    st.set_page_config(
        page_title="MCP-Scanner — AI Agent Security Auditor",
        page_icon="🛡",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_css()

    # Session defaults
    defaults = {
        "config_input": "",
        "findings": None,
        "risk_score": 0,
        "risk_label": "",
        "parsed_config": None,
        "warnings": [],
        "scan_ran": False,
        "sample_picker": "— Select —",
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default

    samples = load_samples()
    history = load_history()
    stats = header_stats(history)

    render_header(stats)

    with st.sidebar:
        enabled_scanners = render_sidebar(samples, history)

    col_in, col_out = st.columns([5, 6], gap="large")

    with col_in:
        config_text, run_clicked = render_input_panel(samples)

    if run_clicked and (config_text or "").strip():
        parsed, err = parse_config(config_text)
        if err:
            st.session_state.findings = None
            st.session_state.scan_ran = False
            st.error(f"❌ {err}")
        else:
            with st.spinner("🛡  Running 7 scanners + LLM enrichment..."):
                findings = run_static_scanners(parsed, enabled_scanners)
                if enabled_scanners.get("tool_poisoning", True):
                    findings, warnings = enrich_with_llm(parsed, findings)
                else:
                    warnings = []
                findings = sort_findings(findings)
                score, label = calculate_risk_score(findings)

                st.session_state.findings = findings
                st.session_state.risk_score = score
                st.session_state.risk_label = label
                st.session_state.parsed_config = parsed
                st.session_state.warnings = warnings
                st.session_state.scan_ran = True

                try:
                    save_report_to_disk(export_json(findings, score, label, parsed))
                except OSError:
                    pass
                append_history(config_text, findings, score)
                st.toast(f"Audit complete · {len(findings)} findings · risk {score}/100",
                         icon="✅")
            st.rerun()

    with col_out:
        render_results_panel()

    render_footer()


if __name__ == "__main__":
    main()

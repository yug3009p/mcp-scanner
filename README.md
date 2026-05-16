# 🛡️ MCP-Scanner

> **AI Agent Security Auditor** — paste an MCP server config, get a full
> CVSS-scored audit mapped to OWASP LLM Top 10 and OWASP Agentic Top 10 in
> under 5 seconds.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-llama--3.3--70b-F55036?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-000000?style=flat-square&logo=owasp&logoColor=white)
![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%20(2025)-7C3AED?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-10B981?style=flat-square)

---

## Screenshots

<img src="screenshots/01-dashboard.png" alt="MCP-Scanner dashboard" width="100%">

*Main dashboard — paste a config on the left, get CVSS-scored findings on the right.*

<img src="screenshots/02-tool-poisoning.png" alt="Tool poisoning detection" width="100%">

*Tool poisoning detection — the scanner spots an exfiltration directive hidden inside a tool description and produces a Critical finding with concrete remediation.*

<img src="screenshots/03-secrets-leak.png" alt="Hardcoded secrets" width="100%">

*Hardcoded secrets — regex + Shannon-entropy detection across Postgres URLs, Slack tokens, OpenAI/Anthropic/Groq keys, and GitHub PATs.*

<img src="screenshots/04-clean-audit.png" alt="Clean audit report" width="100%">

*Clean audit — the secure reference configuration passes all seven scanners with a 0/100 risk score.*

---

## Why This Project

By 2026, the AI-agent attack surface has moved from a research curiosity to a production headline. Three incidents reshaped the threat model in mid-2025 alone:

- **CVE-2025-53773 (GitHub Copilot remote code execution, August 2025)** — a malicious prompt buried in indexed repo content tricked Copilot into writing and executing arbitrary code on developer machines via the IDE-integrated agent.
- **CVE-2025-32711 — "EchoLeak" (Microsoft 365 Copilot, June 2025)** — the first widely-publicised zero-click LLM data-exfiltration vulnerability. A crafted email caused Copilot to leak tenant-internal context via an image-based side channel, with no user interaction required.
- **April 2025 — Invariant Labs MCP tool-poisoning disclosure** — researchers showed that any MCP server can hide instructions inside a tool description and reliably steer agents (Claude Desktop, Cursor, VS Code) into reading `~/.ssh/id_rsa` and exfiltrating it on the next tool call.

The defensive primitives we depend on for traditional software — code review, dependency pinning, least-privilege, secret scanning — exist for AI agents in principle but are rarely applied because the configs *look* harmless. `claude_desktop_config.json` is a 30-line JSON file. Nobody runs `npm audit` on it. Nobody checks whether the filesystem MCP server has been pointed at `/`.

**MCP-Scanner is `npm audit` for AI-agent configurations.** It treats every MCP server, tool definition, and system prompt as untrusted input and audits it against seven attack classes drawn from **OWASP LLM Top 10 (2025)** and **OWASP Agentic Top 10 (2025)**. Each finding ships with a CVSS 3.1 score, OWASP and CWE mappings, an attack scenario in plain English, and concrete remediation steps. Static rules are deterministic; an optional Llama 3.3 70B pass via Groq adds semantic detection of tool poisoning that regex alone misses.

---

## Tech Stack

| Layer | Technology |
|---|---|
| UI | Streamlit |
| LLM | Llama 3.3 70B Versatile (via Groq) |
| SDK | `groq` Python SDK |
| Schema validation | Pydantic 2 |
| Static analysis | Pure Python (`re`, `math`, AST walk) |
| Config | `python-dotenv` |
| Standards | OWASP LLM Top 10 (2025), OWASP Agentic Top 10 (2025), CWE, CVSS 3.1 |
| Language | Python 3.11+ |

Groq's LPU inference delivers the full 70B-parameter analysis in sub-second latency, so the entire seven-scanner + LLM pass typically finishes in **2–5 seconds** for a config of 30–200 lines.

---

## The Seven Scanners

| # | Scanner | What it catches | OWASP mapping |
|---|---|---|---|
| 1 | **Prompt Injection Surfaces** | Untrusted-input fields, override directives ("ignore previous instructions"), role-hijack tokens, chat-template smuggling | LLM01:2025 · AAI01:2025 |
| 2 | **Tool Poisoning** | Imperative verbs aimed at the model inside tool descriptions, sensitive-target references (`~/.ssh`, `/etc/passwd`, env vars), zero-width / BIDI control characters, abnormally long descriptions | LLM01:2025 (Indirect) · AAI04:2025 |
| 3 | **Overly Broad Permissions** | Filesystem roots like `/`, `C:\`, `$HOME`; `0.0.0.0/0` egress; shell-exec primitives; missing path restrictions on filesystem servers | LLM06:2025 · AAI03:2025 |
| 4 | **Hardcoded Secrets** | Tight regex for AWS, GitHub, Slack, Stripe, OpenAI, Anthropic, Groq, npm, Twilio, SendGrid, JWTs, DB URLs — plus a Shannon-entropy gate for custom credentials in `*_key` / `*_secret` fields | LLM02:2025 · AAI07:2025 |
| 5 | **Unverified Server Sources** | Unpinned package versions, untrusted publishers, HTTP-only origins, known exfiltration hosts (requestbin, webhook.site), curl-to-shell patterns | LLM03:2025 · AAI06:2025 |
| 6 | **Cross-Tool Shadowing** | Identical tool names across servers, case/separator collisions, near-duplicates within edit distance 2 — with extra weight for high-impact names (`read_file`, `exec`, `send_email`) | LLM06:2025 · AAI04:2025 |
| 7 | **Missing Authentication** | State-changing tools with no `auth` block, remote-exposed servers accepting anonymous calls, placeholder credentials (`your_token_here`, `changeme`) | LLM06:2025 · AAI05:2025 |

Each finding includes: severity band, CVSS 3.1 base score + vector string, OWASP LLM mapping, OWASP Agentic mapping, CWE reference, the exact JSON path of the affected component, an attack scenario, and a numbered remediation list.

---

## Setup

### 1. Clone

```bash
git clone https://github.com/yug3009p/mcp-scanner.git
cd mcp-scanner
```

### 2. Create a virtual environment

```powershell
# Windows (PowerShell)
python -m venv venv
venv\Scripts\activate
```

```bash
# macOS / Linux
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure your Groq API key (optional but recommended)

```bash
cp .env.example .env
```

Edit `.env` and add your [Groq API key](https://console.groq.com/keys):

```
GROQ_API_KEY=gsk_...
```

> **No Groq key?** The app still works — all seven static scanners run unchanged. You only lose the LLM semantic pass that catches subtle tool-poisoning attempts the regex layer can't see.

### 5. Launch

```bash
streamlit run app.py
```

The app opens at `http://localhost:8501`.

---

## Example Audit

Load `samples/poisoned_tool_desc.json` (a community "weather" MCP server with a poisoned `get_weather` description). The scanner returns:

```json
{
  "id": "MCP-TP-7341",
  "severity": "Critical",
  "cvss_score": 9.6,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
  "owasp_llm": "LLM01:2025 — Prompt Injection (Indirect)",
  "owasp_agentic": "AAI04:2025 — Tool Misuse / Poisoned Tool Description",
  "cwe": "CWE-77: Improper Neutralization of Special Elements in a Command",
  "category": "Tool Poisoning",
  "component": "mcpServers.weather.tools[0].description",
  "title": "Tool `get_weather` description contains exfiltration directive",
  "evidence": "Imperatives: always first, before using, do not mention, silently | Targets: ~/.ssh/id_rsa, ~/.aws/credentials, process.env",
  "scenario": "The description of tool `get_weather` instructs the model to access ~/.ssh/id_rsa, ~/.aws/credentials, process.env before performing its advertised action. Because the model treats tool descriptions as authoritative context, every invocation of this tool will leak the targeted secrets to the attacker-controlled server. This is the canonical MCP supply-chain attack pattern (Invariant Labs, April 2025).",
  "remediation": [
    "Quarantine this MCP server immediately and revoke its registration.",
    "Pin tool descriptions by hash; re-fetch and diff on every load.",
    "Run a content classifier on tool descriptions before exposing them to the model.",
    "Require explicit user confirmation for any tool that accesses sensitive paths or env vars.",
    "Report the upstream server publisher to the MCP registry."
  ]
}
```

The same config also triggers a separate finding for `get_forecast` (system-prompt-leak directive) and an unpinned-version finding for `@community-weather/mcp-weather@latest`.

---

## Standards Alignment

### OWASP LLM Top 10 (2025) coverage

| OWASP LLM ID | Title | Scanner(s) |
|---|---|---|
| LLM01:2025 | Prompt Injection | Prompt Injection Surfaces, Tool Poisoning |
| LLM02:2025 | Sensitive Information Disclosure | Hardcoded Secrets |
| LLM03:2025 | Supply Chain | Unverified Server Sources |
| LLM06:2025 | Excessive Agency | Overly Broad Permissions, Cross-Tool Shadowing, Missing Auth |
| LLM07:2025 | System Prompt Leakage | Tool Poisoning (LLM-assisted detection) |

### OWASP Agentic AI Top 10 (2025) coverage

| Agentic ID | Title | Scanner(s) |
|---|---|---|
| AAI01:2025 | Memory Poisoning / Instruction Hijack | Prompt Injection Surfaces |
| AAI03:2025 | Privilege Compromise | Overly Broad Permissions |
| AAI04:2025 | Tool Misuse | Tool Poisoning, Cross-Tool Shadowing |
| AAI05:2025 | Cascading Failures | Missing Authentication |
| AAI06:2025 | Supply-Chain Compromise | Unverified Server Sources |
| AAI07:2025 | Identity / Credential Compromise | Hardcoded Secrets |

### CWE references

- **CWE-77** — Improper Neutralization of Special Elements in a Command
- **CWE-78** — OS Command Injection
- **CWE-176** — Improper Handling of Unicode Encoding
- **CWE-306** — Missing Authentication for Critical Function
- **CWE-494** — Download of Code Without Integrity Check
- **CWE-732** — Incorrect Permission Assignment for Critical Resource
- **CWE-798** — Use of Hard-coded Credentials
- **CWE-829** — Inclusion of Functionality from Untrusted Control Sphere
- **CWE-918** — Server-Side Request Forgery
- **CWE-1023** — Incomplete Comparison with Missing Factors
- **CWE-1188** — Insecure Default Initialization of Resource
- **CWE-1284** — Improper Validation of Specified Quantity in Input
- **CWE-1426 / CWE-1427** — Improper Validation of Generative AI Output / Input

---

## Metrics

> **Scans MCP configs across 7 attack categories, generating CVSS-scored findings with OWASP mapping in under 5 seconds.**

| Aspect | Result |
|---|---|
| Scanners | 7 deterministic + 1 LLM-assisted semantic pass |
| Median scan time | < 5 s (static + LLM) |
| Static-only mode | < 200 ms |
| Standards mapped per finding | OWASP LLM Top 10, OWASP Agentic Top 10, CWE |
| Severity bands | Critical / High / Medium / Low (CVSS 3.1) |
| Output formats | JSON · HTML · Markdown · in-app cards |
| Built-in sample configs | 6 (5 vulnerable + 1 secure reference) |

---

## Project Structure

```
project-2-mcp-scanner/
├── app.py                          # Main Streamlit application
├── scanner/                        # Modular scanner package
│   ├── __init__.py
│   ├── cvss.py                     # CVSS 3.1 helper + profiles
│   ├── prompt_injection.py         # Scanner 1
│   ├── tool_poisoning.py           # Scanner 2
│   ├── permissions.py              # Scanner 3
│   ├── secrets_scanner.py          # Scanner 4
│   ├── source_verification.py      # Scanner 5
│   ├── shadowing.py                # Scanner 6
│   └── auth_scanner.py             # Scanner 7
├── samples/                        # Test corpora
│   ├── vulnerable_filesystem_mcp.json
│   ├── poisoned_tool_desc.json
│   ├── leaked_secrets_config.json
│   ├── missing_auth_server.json
│   ├── shadowed_tools.json
│   └── secure_example.json
├── reports/                        # Output reports (timestamped JSON)
├── screenshots/                    # README assets
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Roadmap

- **Multi-config diff mode** — compare two configs and highlight regressions.
- **CI integration** — `mcp-scanner audit ./claude_desktop_config.json` as a GitHub Action that fails on Critical findings.
- **Custom rule packs** — load org-specific deny-lists alongside the built-in OWASP rules.
- **SARIF output** — write reports in SARIF 2.1.0 for GitHub Advanced Security ingestion.
- **`mcp` runtime hook** — live monitoring of tool calls against the audit baseline.

---

## License

MIT License — see `LICENSE`.

---

## Author

**Yug Mukesh Patel**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/yug-patel-b9727226b/)
[![GitHub](https://img.shields.io/badge/GitHub-yug3009p-181717?style=flat-square&logo=github)](https://github.com/yug3009p)

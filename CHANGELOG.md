# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- Findings use the official OWASP Top 10 for Agentic Applications (2026) codes (ASI01-ASI05). The
  previous `AAI` codes were not part of the published list. Permissions findings now map per
  check: filesystem ASI03, network egress ASI02, shell execution ASI05. A test enforces valid codes.

### Fixed
- Groq retired `llama-3.3-70b-versatile`, so the optional LLM pass failed. The model is now
  configurable (`GROQ_MODEL`, default `openai/gpt-oss-120b`, verified working).
- Finding IDs were built with Python's randomised `hash()`, so the same config got different IDs on
  every run. IDs now come from a SHA-256 digest (`scanner/ids.py`) and are stable.
- The secrets scanner missed human-chosen plaintext passwords (for example `PGPASSWORD`), which fail
  the entropy check. Values under password-like keys are now flagged, skipping env-var names,
  references, paths and placeholders. Passphrases containing spaces are still not flagged.

### Added
- pytest suite: findings pinned per bundled sample, finding schema checks, secret redaction,
  robustness against malformed configs, and CVSS 3.1 reference scores.
- CI on Ubuntu and Windows (Python 3.11 and 3.12) with ruff.
- SECURITY.md, CONTRIBUTING.md, this changelog.
- Real screenshots captured from the app running against the bundled samples.

### Security
- The optional LLM pass sent the raw config, including any secrets, to Groq. Secrets are now
  redacted before the request (`redact_secrets`), with tests.

### Fixed
- Static tool-poisoning findings were labelled "LLM" in the UI even when no LLM ran.
- README and in-app text claimed timings and parallel execution that were not measured or true.
  The README now gives the measured static scan time (1–5 ms per bundled sample).
- Removed an incident citation from the secrets finding text that did not match the pattern.

## [1.0.0] - 2026-05-16

Not tagged; refers to the first version on `main`.

### Added
- Seven static scanners with CVSS 3.1 scoring and OWASP LLM / Agentic Top 10 mapping, optional
  Groq LLM pass, Streamlit UI and JSON / HTML / Markdown export.

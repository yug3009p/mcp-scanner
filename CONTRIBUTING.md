# Contributing

Issues and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/yug3009p/mcp-scanner.git
cd mcp-scanner
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
ruff check .
```

CI runs the same checks on Ubuntu and Windows for every pull request.

## Adding or changing a scanner rule

1. Keep scanners deterministic and side-effect free: read the config, return a list of findings.
2. Every finding needs `id`, `title`, `severity`, `category`, a CVSS 3.1 score and vector, and
   `evidence`. Redact any secret value before it goes into `evidence`.
3. Add or update a sample in `samples/` that triggers the rule, and update `EXPECTED` in
   `tests/test_scanners.py`. The secure reference config must stay at zero findings.
4. Only set `_llm_assist` to `True` when the LLM pass actually contributed to the finding.

## Test data

Never commit real credentials or configs from a real organisation. Use obviously fake values.

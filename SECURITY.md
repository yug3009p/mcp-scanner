# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub's
**Report a vulnerability** button on the repository's Security tab, or by email to
yug3009p@gmail.com. Include steps to reproduce and, if possible, a minimal config that triggers
the problem. Never send real credentials or a production config.

You can expect an acknowledgement within 7 days. This is a personal open-source project, so fixes
are best-effort.

## How the tool treats input

MCP configs and tool descriptions are untrusted input:

- **Static scanners** only read the JSON; they never execute commands, start servers or fetch the
  packages a config refers to.
- **Secrets** found in a config are redacted in every finding and export, so a report can be shared
  without re-leaking the credential. A test enforces this.
- **Optional LLM pass:** with `GROQ_API_KEY` set, the findings and up to 6,000 characters of the
  config are sent to Groq. Secrets are redacted first, using a broader rule than detection (any
  value under a password/secret/token/key-like name, plus known token formats). Redaction is
  best-effort, so leave the key unset to keep everything on your machine. A config can contain
  text written to manipulate a model, so LLM output is advisory.

## Scope

In scope: this repository's code. Out of scope: vulnerabilities in dependencies (report those
upstream) and in the MCP servers named in the sample configs.

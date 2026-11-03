import json

import pytest

import scanner
from scanner.cvss import build_cvss, severity_from_score

SCANNERS = {
    "prompt_injection": scanner.scan_prompt_injection,
    "tool_poisoning": scanner.scan_tool_poisoning,
    "permissions": scanner.scan_permissions,
    "secrets": scanner.scan_secrets,
    "authentication": scanner.scan_authentication,
    "shadowing": scanner.scan_shadowing,
    "sources": scanner.scan_sources,
}

# Findings per scanner on each bundled sample. If a scanner change moves these
# numbers, update them deliberately after checking the new findings are right.
EXPECTED = {
    "secure_example": {},
    "poisoned_tool_desc": {"tool_poisoning": 2, "sources": 1},
    "leaked_secrets_config": {"prompt_injection": 3, "secrets": 6, "sources": 2},
    "missing_auth_server": {"prompt_injection": 4, "authentication": 6, "sources": 3},
    "shadowed_tools": {"prompt_injection": 1, "authentication": 1, "shadowing": 2, "sources": 2},
    "vulnerable_filesystem_mcp": {"permissions": 2, "authentication": 2, "sources": 2},
}

REQUIRED_FIELDS = {"id", "title", "severity", "category", "cvss_score", "cvss_vector", "evidence"}


def run_all(config: dict) -> dict[str, list[dict]]:
    return {name: fn(config) for name, fn in SCANNERS.items()}


@pytest.mark.parametrize("sample", sorted(EXPECTED))
def test_findings_per_sample(sample, load_sample):
    results = run_all(load_sample(sample))
    counts = {name: len(found) for name, found in results.items() if found}
    assert counts == EXPECTED[sample]


@pytest.mark.parametrize("sample", sorted(EXPECTED))
def test_findings_are_well_formed(sample, load_sample):
    for found in run_all(load_sample(sample)).values():
        for f in found:
            assert REQUIRED_FIELDS <= f.keys(), f.get("id")
            assert f["severity"] in {"Critical", "High", "Medium", "Low"}
            assert 0.0 <= f["cvss_score"] <= 10.0
            assert f["cvss_vector"].startswith("CVSS:3.1/")


def test_secure_reference_config_is_clean(load_sample):
    assert not any(run_all(load_sample("secure_example")).values())


def test_tool_poisoning_detects_exfiltration_directive(load_sample):
    found = scanner.scan_tool_poisoning(load_sample("poisoned_tool_desc"))
    assert any(f["severity"] == "Critical" for f in found)
    # Static regex findings must not claim LLM involvement.
    assert not any(f["_llm_assist"] for f in found)


def test_secret_values_never_appear_in_findings(load_sample):
    config = load_sample("leaked_secrets_config")
    found = scanner.scan_secrets(config)
    assert found
    report_text = json.dumps(found)
    assert "Sup3rS3cr3tPgPass" not in report_text
    assert all("*" in f["evidence"] for f in found)


def test_redaction_before_llm_hides_every_secret(load_sample):
    config = load_sample("leaked_secrets_config")
    redacted = scanner.secrets_scanner.redact_secrets(config)
    text = json.dumps(redacted)
    assert scanner.scan_secrets(redacted) == []
    # Not flagged by the scanner (no high entropy), but still must not leave the machine.
    assert "Sup3rS3cr3tPgPass" not in text
    assert config != redacted  # original is not modified in place
    assert "Sup3rS3cr3tPgPass" in json.dumps(config)


def test_redaction_keeps_placeholders_and_env_var_names():
    redact = scanner.secrets_scanner.redact_secrets
    assert redact({"token_env": "WEATHER_API_TOKEN"}) == {"token_env": "WEATHER_API_TOKEN"}
    assert redact({"api_key": "${API_KEY}"}) == {"api_key": "${API_KEY}"}
    assert redact({"password": "hunter2"}) == {"password": "[REDACTED]"}
    assert redact({"description": "uses a token"}) == {"description": "uses a token"}


def test_scanners_ignore_unexpected_shapes():
    for config in ({}, {"mcpServers": None}, {"mcpServers": {"x": "not-a-dict"}}, {"tools": ["x"]}):
        for fn in SCANNERS.values():
            assert isinstance(fn(config), list)


@pytest.mark.parametrize(
    "metrics,score,severity",
    [
        ({"c": "H", "i": "H", "a": "H"}, 9.8, "Critical"),
        ({"scope": "C", "c": "H", "i": "H", "a": "H"}, 10.0, "Critical"),
        ({"ui": "R", "c": "H"}, 6.5, "Medium"),
        ({"av": "L", "pr": "L", "c": "H", "i": "H", "a": "H"}, 7.8, "High"),
        ({}, 0.0, "None"),
    ],
)
def test_cvss_matches_reference_scores(metrics, score, severity):
    # Reference values from the FIRST CVSS v3.1 calculator.
    result = build_cvss(**metrics)
    assert result.base_score == score
    assert severity_from_score(score) == severity

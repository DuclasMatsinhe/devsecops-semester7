import json

from security_engine.scanners.semgrep import parse_semgrep_results
from security_engine.scanners.pip_audit import parse_pip_audit_results
from security_engine.scanners.gitleaks import parse_gitleaks_results


def load_fixture(filename):
    with open(f"tests/fixtures/{filename}", "r", encoding="utf-8") as file:
        return json.load(file)


def test_parse_semgrep_results():
    data = load_fixture("semgrep_sample.json")

    findings = parse_semgrep_results(data)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.tool == "Semgrep"
    assert finding.severity == "HIGH"
    assert finding.rule_id == (
        "python.flask.security.audit.app-run-param-config."
        "avoid_app_run_with_bad_host"
    )
    assert finding.file == "run.py"
    assert finding.line == 6


def test_parse_pip_audit_results():
    data = load_fixture("pip_audit_sample.json")

    findings = parse_pip_audit_results(data)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.tool == "pip-audit"
    assert finding.severity == "HIGH"
    assert finding.title == "PYSEC-2026-1845"
    assert finding.rule_id == "PYSEC-2026-1845"


def test_parse_gitleaks_results():
    data = load_fixture("gitleaks_sample.json")

    findings = parse_gitleaks_results(data)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.tool == "GitLeaks"
    assert finding.severity == "HIGH"
    assert finding.title == "generic-api-key"
    assert finding.file == "config.py"
    assert finding.line == 12
    assert finding.rule_id == "generic-api-key"

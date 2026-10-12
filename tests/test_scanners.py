
import json
from unittest.mock import patch, Mock

from security_engine.models import ScannerResult
from security_engine.scanners.semgrep import (
    parse_semgrep_results,
    run_semgrep,
)
from security_engine.scanners.pip_audit import (
    parse_pip_audit_results,
)
from security_engine.scanners.gitleaks import (
    parse_gitleaks_results,
)


def load_fixture(filename):
    with open(f"tests/fixtures/{filename}", "r", encoding="utf-8") as file:
        return json.load(file)


# Parser tests


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


# Semgrep execution tests


@patch("security_engine.scanners.semgrep.subprocess.run")
def test_run_semgrep_success_without_findings(mock_run):
    mock_run.return_value = Mock(
        returncode=0,
        stdout=json.dumps({"results": []}),
        stderr="",
    )

    result = run_semgrep()

    assert isinstance(result, ScannerResult)
    assert result.tool == "Semgrep"
    assert result.status == "SUCCESS"
    assert result.findings == []
    assert result.return_code == 0


@patch("security_engine.scanners.semgrep.subprocess.run")
def test_run_semgrep_success_with_findings(mock_run):
    report = {
        "results": [
            {
                "check_id": "test-rule",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {
                    "severity": "ERROR",
                    "message": "Synthetic security finding",
                },
            }
        ]
    }

    mock_run.return_value = Mock(
        returncode=0,
        stdout=json.dumps(report),
        stderr="",
    )

    result = run_semgrep()

    assert result.status == "SUCCESS"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "HIGH"
    assert result.findings[0].file == "app.py"
    assert result.findings[0].line == 10


@patch("security_engine.scanners.semgrep.subprocess.run")
def test_run_semgrep_missing_executable(mock_run):
    mock_run.side_effect = FileNotFoundError()

    result = run_semgrep()

    assert result.status == "ERROR"
    assert "not found" in result.error


@patch("security_engine.scanners.semgrep.subprocess.run")
def test_run_semgrep_invalid_json(mock_run):
    mock_run.return_value = Mock(
        returncode=0,
        stdout="not valid JSON",
        stderr="",
    )

    result = run_semgrep()

    assert result.status == "ERROR"
    assert "invalid report" in result.error


@patch("security_engine.scanners.semgrep.subprocess.run")
def test_run_semgrep_nonzero_exit_with_valid_report(mock_run):
    report = {
        "results": [
            {
                "check_id": "test-rule",
                "path": "app.py",
                "start": {"line": 5},
                "extra": {
                    "severity": "ERROR",
                    "message": "Synthetic finding",
                },
            }
        ]
    }

    mock_run.return_value = Mock(
        returncode=2,
        stdout=json.dumps(report),
        stderr="Synthetic scanner error",
    )

    result = run_semgrep()

    assert result.status == "ERROR"
    assert result.return_code == 2
    assert len(result.findings) == 1
    assert "Synthetic scanner error" in result.error

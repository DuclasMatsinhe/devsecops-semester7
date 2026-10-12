
from security_engine.engine import SecurityValidationEngine
from security_engine.models import SecurityFinding, ScannerResult


def test_engine_collects_findings():
    engine = SecurityValidationEngine()

    finding = SecurityFinding(
        tool="Semgrep",
        severity="HIGH",
        title="Insecure host configuration",
        description="The application is configured with an unsafe host.",
        file="run.py",
        line=6,
        rule_id="flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host",
    )

    engine.add_finding(finding)

    assert len(engine.get_findings()) == 1
    assert engine.get_findings()[0].tool == "Semgrep"


def test_engine_counts_severities():
    engine = SecurityValidationEngine()

    engine.add_findings([
        SecurityFinding(
            tool="Semgrep",
            severity="HIGH",
            title="High finding",
            description="Test finding",
        ),
        SecurityFinding(
            tool="pip-audit",
            severity="MEDIUM",
            title="Medium finding",
            description="Test finding",
        ),
        SecurityFinding(
            tool="Gitleaks",
            severity="LOW",
            title="Low finding",
            description="Test finding",
        ),
    ])

    counts = engine.count_by_severity()

    assert counts["HIGH"] == 1
    assert counts["MEDIUM"] == 1
    assert counts["LOW"] == 1
    assert counts["CRITICAL"] == 0


def test_engine_detects_blocking_finding():
    engine = SecurityValidationEngine()

    engine.add_finding(
        SecurityFinding(
            tool="Semgrep",
            severity="HIGH",
            title="High severity finding",
            description="Test blocking finding",
        )
    )

    assert engine.has_blocking_findings() is True


def test_engine_allows_low_findings():
    engine = SecurityValidationEngine()

    engine.add_finding(
        SecurityFinding(
            tool="Gitleaks",
            severity="LOW",
            title="Low severity finding",
            description="Test non-blocking finding",
        )
    )

    assert engine.has_blocking_findings() is False


def test_engine_summary():
    engine = SecurityValidationEngine()

    engine.add_findings([
        SecurityFinding(
            tool="Semgrep",
            severity="HIGH",
            title="Security issue",
            description="Test finding",
        ),
        SecurityFinding(
            tool="Gitleaks",
            severity="CRITICAL",
            title="Secret detected",
            description="Test finding",
        ),
    ])

    summary = engine.summary()

    assert summary["total_findings"] == 2
    assert summary["highest_severity"] == "CRITICAL"
    assert summary["blocking_findings"] is True


def test_scanner_error_prevents_gate_from_passing():
    engine = SecurityValidationEngine()

    engine.scanner_results.append(
        ScannerResult(
            tool="Semgrep",
            status="ERROR",
            error="Semgrep executable was not found.",
        )
    )

    summary = engine.summary()

    assert summary["blocking_findings"] is False
    assert summary["scanner_errors"] == 1
    assert summary["security_gate_passed"] is False


def test_successful_scan_without_findings_allows_gate_to_pass():
    engine = SecurityValidationEngine()

    engine.scanner_results.append(
        ScannerResult(
            tool="Semgrep",
            status="SUCCESS",
            findings=[],
            return_code=0,
        )
    )

    summary = engine.summary()

    assert summary["scanner_errors"] == 0
    assert summary["security_gate_passed"] is True

def test_security_gate_blocks_high_findings():
    engine = SecurityValidationEngine()

    engine.add_finding(
        SecurityFinding(
            tool="Semgrep",
            severity="HIGH",
            title="SQL injection",
            description="User input is used to construct a SQL query.",
        )
    )

    summary = engine.summary()

    assert summary["blocking_findings"] is True
    assert summary["security_gate_passed"] is False


def test_security_gate_passes_with_only_low_findings():
    engine = SecurityValidationEngine()

    engine.add_finding(
        SecurityFinding(
            tool="Semgrep",
            severity="LOW",
            title="Informational finding",
            description="A non-blocking test finding.",
        )
    )

    summary = engine.summary()

    assert summary["blocking_findings"] is False
    assert summary["security_gate_passed"] is True

from unittest.mock import patch


def test_engine_records_scanner_results():
    engine = SecurityValidationEngine()

    with (
        patch(
            "security_engine.engine.run_semgrep",
            return_value=ScannerResult(
                tool="Semgrep",
                status="SUCCESS",
                findings=[],
                return_code=0,
            ),
        ),
        patch(
            "security_engine.engine.run_pip_audit",
            return_value=ScannerResult(
                tool="pip-audit",
                status="SUCCESS",
                findings=[],
                return_code=0,
            ),
        ),
        patch(
            "security_engine.engine.run_gitleaks",
            return_value=ScannerResult(
                tool="GitLeaks",
                status="SUCCESS",
                findings=[],
                return_code=0,
            ),
        ),
    ):
        engine.run_all_scanners()

    assert len(engine.scanner_results) == 3
    assert engine.has_scanner_errors() is False
    assert engine.summary()["security_gate_passed"] is True


def test_engine_records_scanner_exception():
    engine = SecurityValidationEngine()

    with (
        patch(
            "security_engine.engine.run_semgrep",
            side_effect=RuntimeError("Test scanner failure"),
        ),
        patch(
            "security_engine.engine.run_pip_audit",
            return_value=ScannerResult(
                tool="pip-audit",
                status="SUCCESS",
                findings=[],
                return_code=0,
            ),
        ),
        patch(
            "security_engine.engine.run_gitleaks",
            return_value=ScannerResult(
                tool="GitLeaks",
                status="SUCCESS",
                findings=[],
                return_code=0,
            ),
        ),
    ):
        engine.run_all_scanners()

    assert engine.has_scanner_errors() is True
    assert engine.summary()["scanner_errors"] == 1
    assert engine.summary()["security_gate_passed"] is False


def test_engine_collects_findings_from_successful_scanner():
    engine = SecurityValidationEngine()

    finding = SecurityFinding(
        tool="Semgrep",
        severity="HIGH",
        title="Test vulnerability",
        description="Controlled test finding.",
    )

    with (
        patch(
            "security_engine.engine.run_semgrep",
            return_value=ScannerResult(
                tool="Semgrep",
                status="SUCCESS",
                findings=[finding],
                return_code=0,
            ),
        ),
        patch(
            "security_engine.engine.run_pip_audit",
            return_value=ScannerResult(
                tool="pip-audit",
                status="SUCCESS",
                findings=[],
                return_code=0,
            ),
        ),
        patch(
            "security_engine.engine.run_gitleaks",
            return_value=ScannerResult(
                tool="GitLeaks",
                status="SUCCESS",
                findings=[],
                return_code=0,
            ),
        ),
    ):
        engine.run_all_scanners()

    assert len(engine.get_findings()) == 1
    assert engine.summary()["blocking_findings"] is True
    assert engine.summary()["security_gate_passed"] is False


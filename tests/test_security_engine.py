from security_engine.engine import SecurityValidationEngine
from security_engine.models import SecurityFinding


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

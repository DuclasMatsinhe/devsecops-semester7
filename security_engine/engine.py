
from typing import List

from .models import SecurityFinding, ScannerResult
from .scanners.semgrep import run_semgrep
from .scanners.pip_audit import run_pip_audit
from .scanners.gitleaks import run_gitleaks


class SecurityValidationEngine:
    """Collect and evaluate security findings and scanner outcomes."""

    SEVERITY_LEVELS = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.scanner_results: List[ScannerResult] = []

    def add_finding(self, finding: SecurityFinding):
        """Add one security finding."""
        if not isinstance(finding, SecurityFinding):
            raise TypeError("Expected a SecurityFinding object.")
        self.findings.append(finding)

    def add_findings(self, findings: List[SecurityFinding]):
        """Add multiple security findings."""
        if not all(
            isinstance(finding, SecurityFinding)
            for finding in findings
        ):
            raise TypeError(
                "All findings must be SecurityFinding objects."
            )
        self.findings.extend(findings)

    def run_all_scanners(self):
        """Run scanners and preserve their execution outcomes."""

        self.findings = []
        self.scanner_results = []

        scanners = [
            ("Semgrep", run_semgrep),
            ("pip-audit", run_pip_audit),
            ("GitLeaks", run_gitleaks),
        ]

        for name, scanner in scanners:
            try:
                outcome = scanner()

                if isinstance(outcome, ScannerResult):
                    if outcome.status not in {"SUCCESS", "ERROR"}:
                        raise ValueError(
                            f"Invalid scanner status: {outcome.status}"
                        )

                    if outcome.status == "SUCCESS" and outcome.error:
                        raise ValueError(
                            "A successful scan cannot contain an error."
                        )

                    if not all(
                        isinstance(finding, SecurityFinding)
                        for finding in outcome.findings
                    ):
                        raise ValueError(
                            "Scanner returned invalid finding objects."
                        )

                    outcome.tool = name
                    self.scanner_results.append(outcome)

                    if outcome.status == "SUCCESS":
                        self.add_findings(outcome.findings)

                elif isinstance(outcome, list):
                    self.add_findings(outcome)

                    self.scanner_results.append(
                        ScannerResult(
                            tool=name,
                            status="SUCCESS",
                            findings=outcome,
                        )
                    )

                else:
                    raise TypeError(
                        "Unsupported scanner result type: "
                        f"{type(outcome).__name__}."
                    )

            except Exception as error:
                self.scanner_results.append(
                    ScannerResult(
                        tool=name,
                        status="ERROR",
                        error=f"{type(error).__name__}: {error}",
                    )
                )

        return self.get_findings()

    def get_findings(self) -> List[SecurityFinding]:
        """Return all collected findings."""
        return self.findings

    def has_scanner_errors(self) -> bool:
        """Return True if any scanner failed."""
        return any(
            result.status == "ERROR"
            for result in self.scanner_results
        )

    def count_by_severity(self):
        """Count findings by recognized severity."""
        counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        for finding in self.findings:
            severity = finding.severity.upper()
            if severity in counts:
                counts[severity] += 1

        return counts

    def highest_severity(self):
        """Return the highest recognized severity, if any."""
        recognized = [
            finding.severity.upper()
            for finding in self.findings
            if finding.severity.upper() in self.SEVERITY_LEVELS
        ]

        if not recognized:
            return None

        return max(
            recognized,
            key=self.SEVERITY_LEVELS.get,
        )

    def has_blocking_findings(self, minimum_severity="HIGH"):
        """Check whether findings meet or exceed a severity threshold."""
        minimum_severity = minimum_severity.upper()

        if minimum_severity not in self.SEVERITY_LEVELS:
            raise ValueError(
                f"Unsupported severity threshold: {minimum_severity}"
            )

        threshold = self.SEVERITY_LEVELS[minimum_severity]

        return any(
            self.SEVERITY_LEVELS.get(
                finding.severity.upper(), 0
            ) >= threshold
            for finding in self.findings
        )

    def summary(self):
        """Summarize findings, scanner health, and gate outcome."""
        blocking = self.has_blocking_findings()
        scanner_errors = sum(
            result.status == "ERROR"
            for result in self.scanner_results
        )

        return {
            "total_findings": len(self.findings),
            "severity_counts": self.count_by_severity(),
            "highest_severity": self.highest_severity(),
            "blocking_findings": blocking,
            "scanner_errors": scanner_errors,
            "scanner_results": [
                result.to_dict()
                for result in self.scanner_results
            ],
            "security_gate_passed": (
                not blocking and scanner_errors == 0
            ),
        }

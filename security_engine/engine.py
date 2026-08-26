from typing import List

from .models import SecurityFinding
from .scanners.semgrep import run_semgrep
from .scanners.pip_audit import run_pip_audit
from .scanners.gitleaks import run_gitleaks

class SecurityValidationEngine:
    """Collects and evaluates security findings."""

    SEVERITY_LEVELS = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    def __init__(self):
        self.findings: List[SecurityFinding] = []

    def add_finding(self, finding: SecurityFinding):
        """Add a security finding to the engine."""
        self.findings.append(finding)
    def run_all_scanners(self):
        """Run all configured security scanners and collect their findings."""

        self.findings = []

        scanners = [
            ("Semgrep", run_semgrep),
            ("pip-audit", run_pip_audit),
            ("GitLeaks", run_gitleaks),
        ]

        for name, scanner in scanners:
            try:
                findings = scanner()
                self.add_findings(findings)
            except FileNotFoundError:
                print(f"Warning: {name} is not installed or not available.")
            except Exception as error:
                print(f"Warning: {name} failed: {error}")

        return self.get_findings()
    def add_findings(self, findings: List[SecurityFinding]):
        """Add multiple security findings."""
        self.findings.extend(findings)

    def get_findings(self) -> List[SecurityFinding]:
        """Return all collected findings."""
        return self.findings

    def count_by_severity(self):
        """Count findings by severity."""
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
        """Return the highest severity found."""
        if not self.findings:
            return None

        return max(
            self.findings,
            key=lambda finding: self.SEVERITY_LEVELS.get(
                finding.severity.upper(), 0
            ),
        ).severity.upper()

    def has_blocking_findings(self, minimum_severity="HIGH"):
        """Check whether findings meet or exceed a severity threshold."""
        threshold = self.SEVERITY_LEVELS[minimum_severity.upper()]

        return any(
            self.SEVERITY_LEVELS.get(finding.severity.upper(), 0) >= threshold
            for finding in self.findings
        )

    def summary(self):
        """Return a summary of the security assessment."""
        return {
            "total_findings": len(self.findings),
            "severity_counts": self.count_by_severity(),
            "highest_severity": self.highest_severity(),
            "blocking_findings": self.has_blocking_findings(),
        }

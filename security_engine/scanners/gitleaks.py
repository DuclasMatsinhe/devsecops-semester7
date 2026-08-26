import json
import subprocess

from security_engine.models import SecurityFinding


def parse_gitleaks_results(data):
    """Convert GitLeaks JSON data into SecurityFinding objects."""

    findings = []

    for item in data:
        findings.append(
            SecurityFinding(
                tool="GitLeaks",
                severity="HIGH",
                title=item.get(
                    "RuleID",
                    "GitLeaks secret detected",
                ),
                description=item.get(
                    "Description",
                    "Potential secret detected in the repository.",
                ),
                file=item.get("File"),
                line=item.get("StartLine"),
                rule_id=item.get("RuleID"),
            )
        )

    return findings


def run_gitleaks():
    """Run GitLeaks and convert its JSON output into SecurityFinding objects."""

    result = subprocess.run(
        [
            "gitleaks",
            "detect",
            "--source",
            ".",
            "--report-format",
            "json",
            "--report-path",
            "gitleaks-report.json",
        ],
        capture_output=True,
        text=True,
    )

    try:
        with open("gitleaks-report.json", "r", encoding="utf-8") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

    return parse_gitleaks_results(data)

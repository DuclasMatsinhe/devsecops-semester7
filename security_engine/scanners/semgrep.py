import json
import subprocess

from security_engine.models import SecurityFinding


def parse_semgrep_results(data):
    """Convert Semgrep JSON data into SecurityFinding objects."""

    findings = []

    for item in data.get("results", []):
        extra = item.get("extra", {})

        severity = extra.get("severity", "INFO").upper()

        severity_map = {
            "INFO": "LOW",
            "WARNING": "MEDIUM",
            "ERROR": "HIGH",
        }

        severity = severity_map.get(severity, severity)

        findings.append(
            SecurityFinding(
                tool="Semgrep",
                severity=severity,
                title=item.get(
                    "check_id",
                    "Semgrep finding",
                ),
                description=extra.get(
                    "message",
                    "Semgrep identified a potential security issue.",
                ),
                file=item.get("path"),
                line=item.get("start", {}).get("line"),
                rule_id=item.get("check_id"),
            )
        )

    return findings


def run_semgrep():
    """Run Semgrep and convert its JSON output into SecurityFinding objects."""

    result = subprocess.run(
        [
            "semgrep",
            "--config",
            "auto",
            "--json",
            ".",
        ],
        capture_output=True,
    )

    stdout = result.stdout.decode("utf-8", errors="replace")

    if not stdout.strip():
        return []

    data = json.loads(stdout)

    return parse_semgrep_results(data)

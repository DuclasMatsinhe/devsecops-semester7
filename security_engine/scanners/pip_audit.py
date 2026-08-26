import json
import subprocess

from security_engine.models import SecurityFinding


def parse_pip_audit_results(data):
    """Convert pip-audit JSON data into SecurityFinding objects."""

    findings = []

    for dependency in data.get("dependencies", []):
        package_name = dependency.get("name", "Unknown package")
        package_version = dependency.get("version", "Unknown version")

        for vulnerability in dependency.get("vulns", []):
            findings.append(
                SecurityFinding(
                    tool="pip-audit",
                    severity="HIGH",
                    title=vulnerability.get(
                        "id",
                        f"Vulnerability in {package_name}",
                    ),
                    description=vulnerability.get(
                        "description",
                        f"{package_name} {package_version} has a known vulnerability.",
                    ),
                    rule_id=vulnerability.get("id"),
                )
            )

    return findings


def run_pip_audit():
    """Run pip-audit and convert its JSON output into SecurityFinding objects."""

    result = subprocess.run(
        [
            "pip-audit",
            "-r",
            "requirements.txt",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        return []

    data = json.loads(result.stdout)

    return parse_pip_audit_results(data)

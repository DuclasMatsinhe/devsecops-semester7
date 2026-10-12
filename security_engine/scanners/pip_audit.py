import json
import os
import subprocess
import sys

from security_engine.models import SecurityFinding, ScannerResult


def parse_pip_audit_results(data):
    """Convert pip-audit JSON data into SecurityFinding objects."""

    if not isinstance(data, dict):
        raise ValueError("pip-audit report must contain a JSON object.")

    dependencies = data.get("dependencies", [])

    if not isinstance(dependencies, list):
        raise ValueError("pip-audit dependencies must be a list.")

    findings = []

    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError(
                "pip-audit report contains an invalid dependency."
            )

        package_name = dependency.get("name", "Unknown package")
        package_version = dependency.get("version", "Unknown version")
        vulnerabilities = dependency.get("vulns", [])

        if not isinstance(vulnerabilities, list):
            raise ValueError(
                "Dependency vulnerabilities must be a list."
            )

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError(
                    "pip-audit report contains an invalid vulnerability."
                )

            vulnerability_id = vulnerability.get("id")

            findings.append(
                SecurityFinding(
                    tool="pip-audit",
                    severity="HIGH",
                    title=(
                        vulnerability_id
                        or f"Vulnerability in {package_name}"
                    ),
                    description=vulnerability.get(
                        "description",
                        (
                            f"{package_name} {package_version} "
                            "has a known vulnerability."
                        ),
                    ),
                    rule_id=vulnerability_id,
                )
            )

    return findings


def run_pip_audit():
    """Run pip-audit and return a structured scanner outcome."""

    executable_name = (
        "pip-audit.exe" if os.name == "nt" else "pip-audit"
    )
    executable = os.path.join(
        os.path.dirname(sys.executable),
        executable_name,
    )

    try:
        result = subprocess.run(
            [
                executable,
                "-r",
                "requirements.txt",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    except FileNotFoundError:
        return ScannerResult(
            tool="pip-audit",
            status="ERROR",
            error=f"pip-audit executable was not found: {executable}",
        )

    except OSError as exc:
        return ScannerResult(
            tool="pip-audit",
            status="ERROR",
            error=f"Could not execute pip-audit: {exc}",
        )

    try:
        if not result.stdout.strip():
            raise ValueError("pip-audit produced no JSON output.")

        data = json.loads(result.stdout)
        findings = parse_pip_audit_results(data)

    except (json.JSONDecodeError, ValueError) as exc:
        return ScannerResult(
            tool="pip-audit",
            status="ERROR",
            error=(
                f"pip-audit produced an invalid report: {exc}. "
                f"Exit code: {result.returncode}. "
                f"{result.stderr.strip() or 'No diagnostic provided.'}"
            ),
            return_code=result.returncode,
        )

    # Exit code 0 means no vulnerabilities were reported.
    if result.returncode == 0:
        return ScannerResult(
            tool="pip-audit",
            status="SUCCESS",
            findings=findings,
            return_code=result.returncode,
        )

    # Exit code 1 with parsed findings means vulnerabilities were found.
    if result.returncode == 1 and findings:
        return ScannerResult(
            tool="pip-audit",
            status="SUCCESS",
            findings=findings,
            return_code=result.returncode,
        )

    return ScannerResult(
        tool="pip-audit",
        status="ERROR",
        error=(
            f"pip-audit exited with code {result.returncode}: "
            f"{result.stderr.strip() or 'Unexpected scanner exit status.'}"
        ),
        return_code=result.returncode,
    )
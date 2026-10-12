import json
import os
import subprocess
import sys

from security_engine.models import SecurityFinding, ScannerResult


def parse_semgrep_results(data):
    """Convert Semgrep JSON data into SecurityFinding objects."""

    if not isinstance(data, dict):
        raise ValueError("Semgrep report must contain a JSON object.")

    results = data.get("results", [])

    if not isinstance(results, list):
        raise ValueError("Semgrep report results must be a list.")

    findings = []

    severity_map = {
        "INFO": "LOW",
        "WARNING": "MEDIUM",
        "ERROR": "HIGH",
    }

    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Semgrep report contains an invalid finding.")

        extra = item.get("extra") or {}

        if not isinstance(extra, dict):
            raise ValueError("Semgrep finding has invalid extra data.")

        raw_severity = str(extra.get("severity", "INFO")).upper()
        severity = severity_map.get(raw_severity, raw_severity)

        start = item.get("start") or {}

        if not isinstance(start, dict):
            start = {}

        findings.append(
            SecurityFinding(
                tool="Semgrep",
                severity=severity,
                title=item.get("check_id", "Semgrep finding"),
                description=extra.get(
                    "message",
                    "Semgrep identified a potential security issue.",
                ),
                file=item.get("path"),
                line=start.get("line"),
                rule_id=item.get("check_id"),
            )
        )

    return findings


def run_semgrep():
    """Run Semgrep and return a structured scanner outcome."""

    executable_name = (
        "semgrep.exe" if os.name == "nt" else "semgrep"
    )

    executable = os.path.join(
        os.path.dirname(sys.executable),
        executable_name,
    )

    try:
        result = subprocess.run(
            [
                executable,
                "--config",
                "auto",
                "--json",
                ".",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    except FileNotFoundError:
        return ScannerResult(
            tool="Semgrep",
            status="ERROR",
            error=f"Semgrep executable was not found: {executable}",
        )

    except OSError as exc:
        return ScannerResult(
            tool="Semgrep",
            status="ERROR",
            error=f"Could not execute Semgrep: {exc}",
        )

    try:
        if not result.stdout.strip():
            raise ValueError("Semgrep produced no JSON output.")

        data = json.loads(result.stdout)
        findings = parse_semgrep_results(data)

    except (json.JSONDecodeError, ValueError) as exc:
        return ScannerResult(
            tool="Semgrep",
            status="ERROR",
            error=(
                f"Semgrep produced an invalid report: {exc}. "
                f"Exit code: {result.returncode}. "
                f"{result.stderr.strip() or 'No diagnostic provided.'}"
            ),
            return_code=result.returncode,
        )

    if result.returncode != 0:
        return ScannerResult(
            tool="Semgrep",
            status="ERROR",
            findings=findings,
            error=(
                f"Semgrep exited with code {result.returncode}: "
                f"{result.stderr.strip() or 'Unexpected exit status.'}"
            ),
            return_code=result.returncode,
        )

    return ScannerResult(
        tool="Semgrep",
        status="SUCCESS",
        findings=findings,
        return_code=result.returncode,
    )
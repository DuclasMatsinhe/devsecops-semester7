
import json
import subprocess
from pathlib import Path

from security_engine.models import SecurityFinding, ScannerResult


REPORT_PATH = Path("gitleaks-report.json")


def parse_gitleaks_results(data):
    """Convert GitLeaks JSON data into SecurityFinding objects."""

    if not isinstance(data, list):
        raise ValueError("GitLeaks report must contain a JSON list.")

    findings = []

    for item in data:
        if not isinstance(item, dict):
            raise ValueError("GitLeaks report contains an invalid finding.")

        findings.append(
            SecurityFinding(
                tool="GitLeaks",
                severity="HIGH",
                title=item.get("RuleID", "GitLeaks secret detected"),
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
    """Run GitLeaks and report findings or scanner execution errors."""

    try:
        # Remove an old report so it cannot be mistaken for new output.
        REPORT_PATH.unlink(missing_ok=True)

        result = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                ".",
                "--report-format",
                "json",
                "--report-path",
                str(REPORT_PATH),
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    except FileNotFoundError:
        return ScannerResult(
            tool="GitLeaks",
            status="ERROR",
            error="GitLeaks executable was not found.",
        )
    except OSError as exc:
        return ScannerResult(
            tool="GitLeaks",
            status="ERROR",
            error=f"Could not execute GitLeaks: {exc}",
        )

    # GitLeaks commonly returns 1 when leaks are found.
    # Other non-zero exit codes indicate execution errors.
    if result.returncode not in (0, 1):
        return ScannerResult(
            tool="GitLeaks",
            status="ERROR",
            error=(
                f"GitLeaks exited with code {result.returncode}: "
                f"{result.stderr.strip() or 'No diagnostic provided.'}"
            ),
            return_code=result.returncode,
        )

    try:
        with REPORT_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)

        findings = parse_gitleaks_results(data)

    except FileNotFoundError:
        return ScannerResult(
            tool="GitLeaks",
            status="ERROR",
            error="GitLeaks did not generate its JSON report.",
            return_code=result.returncode,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        return ScannerResult(
            tool="GitLeaks",
            status="ERROR",
            error=f"GitLeaks produced an invalid report: {exc}",
            return_code=result.returncode,
        )
    except OSError as exc:
        return ScannerResult(
            tool="GitLeaks",
            status="ERROR",
            error=f"Could not read the GitLeaks report: {exc}",
            return_code=result.returncode,
        )

    return ScannerResult(
        tool="GitLeaks",
        status="SUCCESS",
        findings=findings,
        return_code=result.returncode,
    )

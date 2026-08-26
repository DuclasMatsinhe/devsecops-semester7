import json
import sys

from .engine import SecurityValidationEngine


def main():
    engine = SecurityValidationEngine()

    findings = engine.run_all_scanners()

    summary = engine.summary()

    print(json.dumps(summary, indent=2))

    if findings:
        print("\nFindings:")
        for finding in findings:
            print(json.dumps(finding.to_dict(), indent=2))

    # Security gate
    if summary["blocking_findings"]:
        print("\nSECURITY GATE: FAILED")
        print("One or more HIGH or CRITICAL findings were detected.")
        return 1

    print("\nSECURITY GATE: PASSED")
    print("No HIGH or CRITICAL findings were detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

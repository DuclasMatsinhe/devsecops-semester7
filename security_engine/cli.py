
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

    # Fail closed: blocking findings OR scanner errors must block the gate.
    if not summary["security_gate_passed"]:
        print("\nSECURITY GATE: FAILED")

        if summary["blocking_findings"]:
            print("Blocking security findings were detected.")

        if summary["scanner_errors"]:
            print("One or more security scanners failed.")

        return 1

    print("\nSECURITY GATE: PASSED")
    print("All scanners succeeded and no blocking findings were detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

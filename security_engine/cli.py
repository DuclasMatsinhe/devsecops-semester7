import json

from .engine import SecurityValidationEngine


def main():
    engine = SecurityValidationEngine()

    findings = engine.run_all_scanners()

    print(json.dumps(engine.summary(), indent=2))

    if findings:
        print("\nFindings:")
        for finding in findings:
            print(json.dumps(finding.to_dict(), indent=2))


if __name__ == "__main__":
    main()

import json
import csv
from pathlib import Path

from security_rules import analyze_resource


def main():
    config_path = Path("sample_config.json")

    
with config_path.open("r", encoding="utf-8") as file:
    config = json.load(file)


    all_findings = []

    print(f"\nSentinelOps Security Report")
    print(f"Environment: {config['project_name']}")
    print("-" * 50)

    for resource in config["resources"]:
        findings = analyze_resource(resource)
        all_findings.extend(findings)

    if not all_findings:
        print("No security findings detected.")

    for finding in all_findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['resource']}: {finding['finding']}"
        )
        print(f"  Recommendation: {finding['recommendation']}")

    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)

    report_path = report_dir / "security_report.csv"

    fieldnames = [
        "resource",
        "severity",
        "finding",
        "recommendation"
    ]

    with report_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_findings)

    print("\n" + "-" * 50)
    print(f"Total findings: {len(all_findings)}")
    print(f"CSV report saved to: {report_path}")


if __name__ == "__main__":
    main()


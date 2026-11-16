"""
gap_analyzer.py
Compares an organization's mapped controls (CSV) against the full NIST CSF 2.0
subcategory list (JSON) and reports coverage gaps by function.

Usage:
    python gap_analyzer.py --controls data/sample_org_controls.csv \
                            --framework data/nist_csf_2_0_subset.json \
                            --output reports/gap_report.json
"""

import argparse
import csv
import json
import os
from collections import defaultdict

STATUS_WEIGHT = {
    "implemented": 1.0,
    "partial": 0.5,
    "not_implemented": 0.0,
}


def load_controls(path):
    """Read the org's control inventory CSV into a list of dicts."""
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_framework(path):
    """Read the NIST CSF 2.0 function/subcategory reference JSON."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def analyze(controls, framework):
    """
    Build a coverage map per function, then flag any subcategory with
    no mapped control (critical gap) or only a partial control (high gap).
    """
    mapped = {c["csf_subcategory"]: c for c in controls}
    results = {"functions": {}, "summary": {}}

    total_subcats = 0
    covered = 0
    critical_gaps = []
    high_gaps = []

    for func_code, func in framework.items():
        func_result = {"name": func["name"], "subcategories": {}}
        for subcat in func["subcategories"]:
            total_subcats += 1
            control = mapped.get(subcat)
            if control is None:
                status = "not_implemented"
                weight = 0.0
                critical_gaps.append(subcat)
            else:
                status = control["status"]
                weight = STATUS_WEIGHT.get(status, 0.0)
                if status == "partial":
                    high_gaps.append(subcat)
                if weight >= 1.0:
                    covered += 1
            func_result["subcategories"][subcat] = {
                "status": status,
                "control_id": control["control_id"] if control else None,
                "owner": control["owner"] if control else None,
            }
        results["functions"][func_code] = func_result

    coverage_pct = round((covered / total_subcats) * 100, 1) if total_subcats else 0.0
    results["summary"] = {
        "total_subcategories": total_subcats,
        "fully_covered": covered,
        "coverage_pct": coverage_pct,
        "critical_gaps": critical_gaps,
        "high_gaps": high_gaps,
    }
    return results


def print_summary(results):
    s = results["summary"]
    print("=" * 52)
    print("  NIST CSF 2.0 Compliance Gap Analysis")
    print("=" * 52)
    print(f"  Total Subcategories : {s['total_subcategories']}")
    print(f"  Fully Covered       : {s['fully_covered']}  ({s['coverage_pct']}% coverage)")
    print(f"  Critical Gaps       : {len(s['critical_gaps'])}")
    print(f"  High (Partial) Gaps : {len(s['high_gaps'])}")
    print("=" * 52)
    if s["critical_gaps"]:
        print("\nCritical gaps (no control mapped):")
        for g in s["critical_gaps"]:
            print(f"  [CRITICAL] {g}")
    if s["high_gaps"]:
        print("\nHigh gaps (partially implemented):")
        for g in s["high_gaps"]:
            print(f"  [HIGH] {g}")


def main():
    parser = argparse.ArgumentParser(description="NIST CSF 2.0 gap analyzer")
    parser.add_argument("--controls", required=True, help="Path to org controls CSV")
    parser.add_argument("--framework", required=True, help="Path to CSF 2.0 reference JSON")
    parser.add_argument("--output", default=None, help="Optional path to write JSON report")
    args = parser.parse_args()

    controls = load_controls(args.controls)
    framework = load_framework(args.framework)
    results = analyze(controls, framework)
    print_summary(results)

    if args.output:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\nFull report written to {args.output}")


if __name__ == "__main__":
    main()

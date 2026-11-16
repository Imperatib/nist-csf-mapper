"""
evidence_checklist.py
Generates an audit-ready evidence checklist from a mapped controls CSV —
one row per control, with the evidence artifact an auditor would expect
to see and the owner responsible for producing it.

Usage:
    python evidence_checklist.py --controls data/sample_org_controls.csv \
                                  --output reports/evidence_checklist.csv
"""

import argparse
import csv
import os

# Lightweight heuristic: map keywords in the control description to the
# evidence artifact type an auditor would typically request.
EVIDENCE_HINTS = [
    (["mfa", "access", "privileged", "review"], "Access review report / screenshots of MFA + RBAC config"),
    (["policy", "published", "documented"], "Signed policy document with version/date"),
    (["monitoring", "continuous", "log"], "SIEM dashboard export / log retention config"),
    (["incident response", "plan", "tested"], "IR plan document + most recent tabletop exercise report"),
    (["backup", "recovery"], "Backup job logs + most recent restore test results"),
    (["vendor", "risk assessment"], "Vendor risk assessment questionnaire + sign-off"),
    (["inventory", "cmdb", "asset"], "Asset inventory export (CMDB report)"),
]


def guess_evidence(description):
    desc_lower = description.lower()
    for keywords, evidence in EVIDENCE_HINTS:
        if any(k in desc_lower for k in keywords):
            return evidence
    return "Evidence artifact TBD — confirm with control owner"


def load_controls(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build_checklist(controls):
    rows = []
    for c in controls:
        rows.append({
            "control_id": c["control_id"],
            "csf_subcategory": c["csf_subcategory"],
            "status": c["status"],
            "owner": c["owner"],
            "evidence_artifact": guess_evidence(c["description"]),
            "collected": "",  # left blank for the analyst to check off
        })
    return rows


def write_checklist(rows, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fieldnames = ["control_id", "csf_subcategory", "status", "owner", "evidence_artifact", "collected"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="Generate an audit evidence checklist")
    parser.add_argument("--controls", required=True, help="Path to org controls CSV")
    parser.add_argument("--output", required=True, help="Path to write the checklist CSV")
    args = parser.parse_args()

    controls = load_controls(args.controls)
    rows = build_checklist(controls)
    write_checklist(rows, args.output)

    print(f"Generated evidence checklist for {len(rows)} controls -> {args.output}")


if __name__ == "__main__":
    main()

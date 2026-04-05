#!/usr/bin/env python3
"""
csf_mapper.py — NIST CSF 2.0 & ISO 27001 Control Mapper
Author: [Your Name] | ISC2 SSCP | CySA+
Description:
    Maps an organization's security controls to NIST CSF 2.0 and ISO 27001:2022
    via keyword matching and manual tagging. Produces a structured compliance
    mapping report with gap analysis and remediation prioritization.
"""

import csv
import json
import re
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import track
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    class Console:
        def print(self, *a, **k): print(*a)
    console = Console()

# ── Embedded NIST CSF 2.0 Subcategory Reference (abbreviated) ────────────────
# Full library loaded from data/nist_csf_2_0.json in production
NIST_CSF_SUBCATEGORIES = {
    "GV.OC-01": {"function": "GOVERN", "category": "Organizational Context", "description": "Mission, stakeholder expectations, and legal requirements are understood and inform security strategy"},
    "GV.RM-01": {"function": "GOVERN", "category": "Risk Management Strategy", "description": "Risk management objectives are established and agreed upon by stakeholders"},
    "ID.AM-01": {"function": "IDENTIFY", "category": "Asset Management", "description": "Inventories of hardware managed by the organization are maintained"},
    "ID.AM-02": {"function": "IDENTIFY", "category": "Asset Management", "description": "Inventories of software, services, and systems managed by the organization are maintained"},
    "ID.RA-01": {"function": "IDENTIFY", "category": "Risk Assessment", "description": "Vulnerabilities in assets are identified, validated, and recorded"},
    "ID.RA-03": {"function": "IDENTIFY", "category": "Risk Assessment", "description": "Internal and external threats to the organization are identified and recorded"},
    "PR.AA-01": {"function": "PROTECT", "category": "Identity Management & Access Control", "description": "Identities and credentials for authorized users, services, and hardware are managed"},
    "PR.AA-02": {"function": "PROTECT", "category": "Identity Management & Access Control", "description": "Identities are proofed and bound to credentials based on context"},
    "PR.AA-05": {"function": "PROTECT", "category": "Identity Management & Access Control", "description": "Access permissions, entitlements, and authorizations are defined in a policy and managed"},
    "PR.DS-01": {"function": "PROTECT", "category": "Data Security", "description": "Data at rest is protected"},
    "PR.DS-02": {"function": "PROTECT", "category": "Data Security", "description": "Data in transit is protected"},
    "PR.IR-01": {"function": "PROTECT", "category": "Technology Infrastructure Resilience", "description": "Networks and environments are protected from unauthorized logical access and usage"},
    "DE.AE-02": {"function": "DETECT", "category": "Adverse Event Analysis", "description": "Potentially adverse events are analyzed to better characterize them"},
    "DE.AE-06": {"function": "DETECT", "category": "Adverse Event Analysis", "description": "Information on adverse events is provided to authorized staff and tools"},
    "DE.CM-01": {"function": "DETECT", "category": "Continuous Monitoring", "description": "Networks and network services are monitored to find potentially adverse events"},
    "DE.CM-03": {"function": "DETECT", "category": "Continuous Monitoring", "description": "Personnel activity and technology usage are monitored to find potentially adverse events"},
    "DE.CM-09": {"function": "DETECT", "category": "Continuous Monitoring", "description": "Computing hardware and software, runtime environments are monitored"},
    "RS.MA-01": {"function": "RESPOND", "category": "Incident Management", "description": "The incident response plan is executed in coordination with relevant third parties"},
    "RS.MA-02": {"function": "RESPOND", "category": "Incident Management", "description": "Incidents are triaged to support triage, prioritization, and handoffs"},
    "RS.AN-03": {"function": "RESPOND", "category": "Incident Analysis", "description": "Analysis is performed to establish what has taken place during an incident"},
    "RS.CO-02": {"function": "RESPOND", "category": "Incident Response Reporting & Communication", "description": "Internal and external stakeholders are notified of incidents"},
    "RC.RP-01": {"function": "RECOVER", "category": "Incident Recovery Plan Execution", "description": "The recovery portion of the incident response plan is executed"},
    "RC.CO-03": {"function": "RECOVER", "category": "Incident Recovery Communication", "description": "Recovery activities and progress in restoring operational capabilities are communicated"},
}

# ── Keyword → CSF Subcategory mapping for auto-tagging ───────────────────────
KEYWORD_MAP = {
    "asset inventory": ["ID.AM-01", "ID.AM-02"],
    "vulnerability": ["ID.RA-01"],
    "threat": ["ID.RA-03"],
    "mfa": ["PR.AA-01", "PR.AA-02"],
    "multi-factor": ["PR.AA-01", "PR.AA-02"],
    "access control": ["PR.AA-05"],
    "encryption": ["PR.DS-01", "PR.DS-02"],
    "firewall": ["PR.IR-01"],
    "network segment": ["PR.IR-01"],
    "siem": ["DE.CM-01", "DE.AE-02"],
    "monitoring": ["DE.CM-01", "DE.CM-09"],
    "log": ["DE.CM-03", "DE.AE-06"],
    "incident response": ["RS.MA-01", "RS.MA-02", "RS.AN-03"],
    "playbook": ["RS.MA-01"],
    "forensic": ["RS.AN-03"],
    "notification": ["RS.CO-02"],
    "recovery": ["RC.RP-01", "RC.CO-03"],
    "backup": ["RC.RP-01"],
    "risk": ["GV.RM-01"],
    "policy": ["GV.OC-01"],
}


class CSFMapper:
    def __init__(self, csf_data: dict = None):
        self.csf = csf_data or NIST_CSF_SUBCATEGORIES
        self.mapped_controls = []
        self.all_subcategories = set(self.csf.keys())
        self.covered_subcategories = set()

    def auto_tag(self, control_text: str) -> list[str]:
        """Auto-map control text to CSF subcategories via keyword matching."""
        text = control_text.lower()
        matched = set()
        for keyword, subcats in KEYWORD_MAP.items():
            if keyword in text:
                matched.update(subcats)
        return list(matched)

    def map_control(self, control: dict) -> dict:
        """Map a single organizational control to CSF subcategories."""
        name = control.get("control_name", "")
        description = control.get("description", "")
        tool = control.get("tool_or_system", "")
        status = control.get("implementation_status", "Implemented").lower()
        manual_tags = [t.strip() for t in control.get("csf_tags", "").split(",") if t.strip()]

        combined_text = f"{name} {description} {tool}"
        auto_tags = self.auto_tag(combined_text)
        all_tags = list(set(auto_tags + manual_tags))

        # Validate tags against known subcategories
        valid_tags = [t for t in all_tags if t in self.csf]

        if status == "implemented":
            self.covered_subcategories.update(valid_tags)

        mapped = {
            "control_name": name,
            "tool_or_system": tool,
            "implementation_status": status,
            "csf_subcategories": valid_tags,
            "csf_functions": list(set(self.csf[t]["function"] for t in valid_tags)),
            "description": description,
        }
        self.mapped_controls.append(mapped)
        return mapped

    def run_gap_analysis(self) -> dict:
        """Identify NIST CSF subcategories with no mapped controls."""
        gaps = self.all_subcategories - self.covered_subcategories
        gap_details = []
        for subcat_id in sorted(gaps):
            subcat = self.csf[subcat_id]
            gap_details.append({
                "subcategory_id": subcat_id,
                "function": subcat["function"],
                "category": subcat["category"],
                "description": subcat["description"],
                "risk_level": self._estimate_gap_risk(subcat_id)
            })

        # Sort by risk
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        gap_details.sort(key=lambda x: risk_order.get(x["risk_level"], 4))
        return gap_details

    def _estimate_gap_risk(self, subcat_id: str) -> str:
        """Estimate risk level of an uncovered subcategory."""
        HIGH_RISK_SUBCATS = {"DE.CM-01", "DE.CM-09", "PR.AA-01", "PR.AA-05",
                              "RS.MA-01", "ID.RA-01", "PR.DS-01", "PR.DS-02"}
        CRITICAL_SUBCATS  = {"RS.MA-02", "DE.AE-02", "PR.IR-01", "ID.RA-03"}
        if subcat_id in CRITICAL_SUBCATS:  return "CRITICAL"
        if subcat_id in HIGH_RISK_SUBCATS: return "HIGH"
        return "MEDIUM"

    def generate_report(self) -> dict:
        """Build the full compliance mapping report."""
        gaps = self.run_gap_analysis()
        coverage_pct = (len(self.covered_subcategories) / len(self.all_subcategories)) * 100

        return {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "framework": "NIST CSF 2.0",
                "author": "[Your Name]"
            },
            "coverage_summary": {
                "total_subcategories": len(self.all_subcategories),
                "covered_subcategories": len(self.covered_subcategories),
                "coverage_percentage": round(coverage_pct, 1),
                "gap_count": len(gaps),
                "critical_gaps": len([g for g in gaps if g["risk_level"] == "CRITICAL"]),
                "high_gaps": len([g for g in gaps if g["risk_level"] == "HIGH"]),
            },
            "mapped_controls": self.mapped_controls,
            "compliance_gaps": gaps
        }

    def print_summary(self, report: dict):
        """Print a formatted summary to the console."""
        s = report["coverage_summary"]
        console.print("\n╔══════════════════════════════════════════════════╗")
        console.print(  "║      NIST CSF 2.0 Compliance Gap Analysis        ║")
        console.print(  "╠══════════════════════════════════════════════════╣")
        console.print(f"║  Total Subcategories : {s['total_subcategories']:<26}║")
        console.print(f"║  Controls Mapped     : {s['covered_subcategories']} ({s['coverage_percentage']}% coverage){'':<8}║")
        console.print(f"║  Gaps Identified     : {s['gap_count']:<26}║")
        console.print(f"║    ├─ Critical Gaps  : {s['critical_gaps']:<26}║")
        console.print(f"║    └─ High Gaps      : {s['high_gaps']:<26}║")
        console.print(  "╚══════════════════════════════════════════════════╝\n")

        top_gaps = [g for g in report["compliance_gaps"] if g["risk_level"] in ("CRITICAL", "HIGH")][:5]
        if top_gaps:
            console.print("Top Priority Gaps:")
            for g in top_gaps:
                icon = "🔴" if g["risk_level"] == "CRITICAL" else "🟠"
                console.print(f"  {icon} [{g['risk_level']}] {g['subcategory_id']} — {g['description'][:70]}...")


def load_csv(path: str) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def main():
    parser = argparse.ArgumentParser(description="NIST CSF 2.0 Compliance Mapper")
    parser.add_argument("--input",  required=True, help="CSV of org controls")
    parser.add_argument("--output", default="reports/", help="Output directory")
    parser.add_argument("--full-report", action="store_true", help="Generate full JSON + console report")
    args = parser.parse_args()

    controls = load_csv(args.input)
    console.print(f"[*] Loaded {len(controls)} controls from {args.input}")

    mapper = CSFMapper()
    for ctrl in controls:
        mapper.map_control(ctrl)

    report = mapper.generate_report()
    mapper.print_summary(report)

    Path(args.output).mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
    out_path = Path(args.output) / f"csf_mapping_{ts}.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    console.print(f"\n[✓] Full report saved: {out_path}")


if __name__ == "__main__":
    main()

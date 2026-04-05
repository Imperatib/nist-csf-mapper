# NIST CSF Compliance Mapper

**Author:** Brandon Imperati | ISC2 SSCP | CySA+ | CompTIA Security+  
**Tools:** Python · Excel/CSV · NIST CSF 2.0 · ISO 27001  
**Focus:** GRC Automation · Compliance Evidence Mapping · Risk Assessment

---

## Overview

A Python-based compliance automation tool that maps organizational security controls to NIST Cybersecurity Framework (CSF) 2.0 and ISO 27001:2022 requirements. Designed to eliminate manual spreadsheet work for compliance analysts — automatically cross-referencing controls, generating evidence checklists, and producing audit-ready gap analysis reports.

Built from firsthand GRC experience conducting security audits and translating technical controls into business risk language.

---

## Repository Structure

```
nist-csf-mapper/
├── csf_mapper.py                  # Core mapping engine
├── gap_analyzer.py                # Gap analysis & remediation prioritizer
├── evidence_checklist.py         # Auto-generate audit evidence checklists
├── report_generator.py            # HTML/CSV compliance report builder
├── data/
│   ├── nist_csf_2_0.json         # Full NIST CSF 2.0 control library
│   ├── iso_27001_2022.json       # ISO 27001:2022 Annex A controls
│   ├── nist_iso_crosswalk.json   # NIST ↔ ISO 27001 crosswalk mapping
│   └── sample_org_controls.csv  # Example organization control inventory
├── templates/
│   ├── gap_report_template.html  # HTML report template
│   └── evidence_checklist.xlsx   # Excel evidence collection template
└── docs/
    ├── usage_guide.md
    └── control_taxonomy.md
```

---

## Featured Scripts

### `csf_mapper.py` — Core Control Mapper
Maps an organization's existing controls to NIST CSF 2.0 Functions/Categories/Subcategories and simultaneously cross-references to ISO 27001 Annex A controls via built-in crosswalk.

**Input:** CSV of organizational controls (tool, owner, status, description)  
**Output:** Structured JSON with full NIST/ISO mapping + coverage metrics

### `gap_analyzer.py` — Compliance Gap Analysis
Compares mapped controls against the full NIST CSF 2.0 framework to identify:
- Uncovered subcategories (compliance gaps)
- Partially implemented controls
- High-risk gaps (weighted by CSF Tier and asset criticality)
- Prioritized remediation roadmap

### `evidence_checklist.py` — Audit Evidence Generator
Produces audit-ready evidence checklists for each mapped control, specifying:
- Required evidence artifacts (logs, screenshots, policies, configs)
- Evidence owner and collection deadline
- Audit question wording for each subcategory

---

## NIST CSF 2.0 Function Coverage

| Function | Subcategories | Tool Coverage |
|----------|--------------|---------------|
| GOVERN (GV) | 6 categories | Policy & risk management mapping |
| IDENTIFY (ID) | 5 categories | Asset & risk inventory mapping |
| PROTECT (PR) | 6 categories | Control implementation mapping |
| DETECT (DE) | 3 categories | Monitoring & detection mapping |
| RESPOND (RS) | 4 categories | IR plan mapping |
| RECOVER (RC) | 3 categories | Recovery plan mapping |

---

## Quick Start

```bash
# Install dependencies
pip install pandas openpyxl jinja2 rich

# Map your controls
python csf_mapper.py --input data/sample_org_controls.csv --output reports/

# Run gap analysis
python gap_analyzer.py --mapped reports/mapped_controls.json --tier 2

# Generate evidence checklist
python evidence_checklist.py --mapped reports/mapped_controls.json --format xlsx

# Full pipeline (map → analyze → report)
python csf_mapper.py --input your_controls.csv --full-report --output reports/
```

---

## Sample Output

```
╔══════════════════════════════════════════════════╗
║      NIST CSF 2.0 Compliance Gap Analysis        ║
╠══════════════════════════════════════════════════╣
║  Total Subcategories : 106                       ║
║  Controls Mapped     : 78  (73.6% coverage)      ║
║  Gaps Identified     : 28                        ║
║    ├─ Critical Gaps  :  6  (requires remediation)║
║    ├─ High Gaps      : 11                        ║
║    └─ Medium Gaps    : 11                        ║
╚══════════════════════════════════════════════════╝

Top 3 Critical Gaps:
  [CRITICAL] DE.CM-09 — No continuous monitoring of computing hardware
  [CRITICAL] GV.OC-05 — Outcomes not communicated to suppliers
  [CRITICAL] PR.AA-05 — Access permissions not reviewed quarterly
```

---

## Use Cases

- **Pre-audit preparation:** Map controls before an external audit to identify gaps
- **Executive reporting:** Translate technical controls to business risk language
- **Multi-framework compliance:** Single input maps to both NIST CSF and ISO 27001
- **Evidence collection:** Generate structured checklists for auditors

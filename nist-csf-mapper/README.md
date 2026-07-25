# NIST CSF Compliance Mapper

**Author:** Brandon Imperati | ISC2 SSCP | CySA+ | CompTIA Security+
**Tools:** Python
**Focus:** GRC Automation · Compliance Control Mapping · Gap Analysis

---

## Overview

A small Python toolkit for GRC work: map organizational controls to NIST CSF 2.0, identify coverage gaps, and generate an audit-ready evidence checklist. Built out of hands-on audit experience translating technical controls into business-risk language.

---

## What's Here

```
nist-csf-mapper/
├── csf_mapper.py            # Core control-to-framework mapping logic
├── gap_analyzer.py          # Compares mapped controls against full CSF 2.0, reports gaps
├── evidence_checklist.py    # Generates an audit evidence checklist from mapped controls
├── data/
│   ├── nist_csf_2_0_full.json      # Full NIST CSF 2.0 reference — all 106 subcategories
│   ├── nist_csf_2_0_subset.json    # Smaller subset, useful for quick demos/testing
│   └── sample_org_controls.csv     # Example organization control inventory
└── README.md
```

---

## Quick Start

```bash
pip install --break-system-packages -r requirements.txt   # (or: no extra deps needed — stdlib only)

# Run a gap analysis against the full NIST CSF 2.0 framework (106 subcategories)
python gap_analyzer.py --controls data/sample_org_controls.csv \
                        --framework data/nist_csf_2_0_full.json \
                        --output reports/gap_report.json

# Generate an evidence checklist
python evidence_checklist.py --controls data/sample_org_controls.csv \
                              --output reports/evidence_checklist.csv
```

Sample output from `gap_analyzer.py` against the full 106-subcategory framework with the included (intentionally sparse) sample control set:

```
====================================================
  NIST CSF 2.0 Compliance Gap Analysis
====================================================
  Total Subcategories : 106
  Fully Covered       : 4  (3.8% coverage)
  Critical Gaps       : 98
  High (Partial) Gaps : 2
====================================================
```

*(Swap `data/sample_org_controls.csv` with your own control inventory to run against real data — coverage percentage will rise accordingly.)*

---

## NIST CSF 2.0 Functions Referenced

| Function      | Focus                             |
| ------------- | ---------------------------------- |
| GOVERN (GV)   | Policy & risk management           |
| IDENTIFY (ID) | Asset & risk inventory             |
| PROTECT (PR)  | Control implementation             |
| DETECT (DE)   | Monitoring & detection             |
| RESPOND (RS)  | Incident response planning         |
| RECOVER (RC)  | Recovery planning                  |

---

## Roadmap

- [ ] ISO 27001:2022 Annex A crosswalk mapping (currently referenced conceptually in `csf_mapper.py`; formal mapping table in progress)
- [ ] HTML report export
- [ ] CLI flag to toggle between full-framework and subset mode

---

## Background

Built from firsthand experience conducting security audits and translating technical controls into business-risk language for leadership.

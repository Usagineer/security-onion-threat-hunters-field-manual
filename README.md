# Security Onion Threat Hunter's Field Manual

A workflow-oriented threat hunting manual for **Security Onion 2.x** (Elastic stack + Zeek + Suricata + Elastic Agent/endpoint telemetry).

This is a *living field manual*. The source of truth is **Markdown**; Word (`.docx`) and PDF releases are generated from it. That gives us version history, easy search/diff, and a low-friction path to contribute new hunts as Security Onion and the threat landscape evolve.

---

## Design philosophy

Most hunting cheat sheets are organized by MITRE ATT&CK tactic. This manual is organized by **how an analyst actually investigates an alert in Security Onion**:

1. **Find a suspicious IP** (Phase 1)
2. **Investigate that IP** end to end (Phase 2 — the Master IP Pivot)
3. Drill into specific tactics (Phases 3–13)
4. Reach for **pivot cheat sheets** when you just need the next move (Phase 14)

Every hunt is designed to be kept open on a second monitor and used to *drive* an investigation — never stop to think about the next step.

---

## Every hunt uses the same template

| Field | Meaning |
|---|---|
| **ATT&CK** | MITRE technique ID(s) |
| **Confidence** | 🟢 Low (often benign) · 🟡 Medium (worth investigating) · 🔴 High (strong malicious indicator) |
| **Difficulty** | 🟢 Easy · 🟡 Intermediate · 🔴 Advanced |
| **Hunt Time** | Rough estimate (2 / 5 / 15 / 30 min) |
| **Why hunt this?** | The hypothesis / attacker behavior |
| **Steps** | Copy/paste queries, one per code block |
| **Look for** | What a true positive looks like |
| **Next Pivots** | Where to go if you find something |
| **Analyst Notes** | Normal vs. suspicious context |
| **Investigation Checklist** | Repeatable evidence-handling steps |

Confidence and difficulty are **independent**: an easy hunt can surface a high-confidence finding, and an advanced hunt can turn up something benign.

---

## Repository layout

```
.
├── README.md                     ← you are here
├── CONTRIBUTING.md               ← how to add/edit a hunt
├── Makefile                      ← build .docx / .pdf from Markdown
├── manual/
│   ├── 00-front-matter.md
│   ├── phase-01-find-suspicious-ips.md   ← Phase 1 (this release)
│   └── ... (phases 2–14 added over time)
├── templates/
│   └── hunt-template.md          ← copy this to start a new hunt
└── build/                        ← generated .docx / .pdf (gitignored)
```

## Building Word / PDF releases

Requires [pandoc](https://pandoc.org/). PDF additionally requires a LaTeX engine (or use the `--pdf-engine=weasyprint` alternative).

```bash
make docx      # build build/phase-01-find-suspicious-ips.docx
make pdf       # build the PDF
make all       # everything
```

See the `Makefile` for details.

---

## Field / query conventions

All queries target **Security Onion 2.x** using Elastic Common Schema (ECS) field names as exposed in the SOC **Hunt** and **Dashboards** interfaces (Lucene/KQL-style `field:value`). Where a Zeek- or Suricata-specific field is needed it is called out explicitly.

Queries are shown in bare code blocks so they can be copied directly into the Security Onion search bar with no reformatting.

---

## Status

| Phase | Title | Status |
|---|---|---|
| 1 | Find Suspicious IPs | ✅ v1 |
| 2 | Investigate the Suspicious IP (Master IP Pivot) | 🔜 |
| 3 | Initial Access | 🔜 |
| 4 | Discovery | 🔜 |
| 5 | Credential Access | 🔜 |
| 6 | Lateral Movement | 🔜 |
| 7 | Persistence | 🔜 |
| 8 | Command & Control | 🔜 |
| 9 | Exfiltration | 🔜 |
| 10 | Malware / Execution | 🔜 |
| 11 | Active Directory / Windows Event IDs | 🔜 |
| 12 | ICS / OT | 🔜 |
| 13 | IOC Hunting | 🔜 |
| 14 | Pivot Cheat Sheets | 🔜 |

---

> **Disclaimer:** For authorized defensive security operations, threat hunting, and education only. Validate every query against your own environment and Security Onion version before relying on it in production.

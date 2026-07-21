<div style="text-align:center">

# Security Onion Threat Hunter's Field Manual

### A workflow-driven hunting guide for Security Onion 2.x
#### Zeek · Suricata · Elastic · Endpoint

*Version 1 — Phase 1: Find Suspicious IPs*

</div>

---

## How to use this manual

This manual is built around a single idea: **an investigation is a sequence of pivots, and you should never have to stop and wonder what the next one is.**

It is organized the way analysts actually work, not the way frameworks are catalogued:

- **Phase 1 — Find Suspicious IPs.** You start here when you have *nothing*. These hunts surface a host, a destination, or a conversation worth looking at.
- **Phase 2 — Master IP Pivot.** The moment you have an IP, you go here and run it through a fixed pivot chain (SMB → RDP → WinRM → DNS → HTTP → TLS → Suricata → Endpoint).
- **Phases 3–13** drill into specific attacker behavior (initial access, discovery, credential access, lateral movement, persistence, C2, exfiltration, malware, Active Directory, ICS/OT, IOC hunting).
- **Phase 14 — Pivot Cheat Sheets.** The "don't think, just hunt" section: *if you found X, go run Y.*

### Reading a hunt

Each hunt is a self-contained card:

- The **header table** tells you at a glance whether it's worth your time right now (ATT&CK mapping, confidence, difficulty, expected time).
- The **steps** are copy/paste queries. Every query sits alone in a code block so you can drop it straight into the Security Onion search bar.
- **Next Pivots** tells you where to go the instant you find something.
- **Analyst Notes** keeps you honest about what's normal in a real network.

### Confidence vs. difficulty

These are two different axes and this manual keeps them separate:

- **Confidence** = how strongly the *finding* suggests malicious activity.
- **Difficulty** = how hard the *hunt* is to run and interpret.

An easy hunt (🟢 difficulty) can produce a high-confidence hit (🔴). An advanced hunt can end in "benign." Don't conflate them.

### A word on the query language

Security Onion 2.x runs on the Elastic stack. Queries here use **Elastic Common Schema (ECS)** field names in the Lucene/KQL `field:value` style used by the SOC **Hunt** and **Dashboards** interfaces. Where a field is specific to a Zeek log or a Suricata event, the dataset is named explicitly (e.g. `event.dataset:zeek.dns`).

> **Adjust for your environment.** Field mappings, enabled Zeek scripts, and log retention vary between deployments and Security Onion versions. Treat every query as a starting point and confirm the fields exist in your data before trusting a null result.

---

## Legend

| Symbol | Meaning |
|---|---|
| 🟢 | Low confidence / Easy difficulty |
| 🟡 | Medium confidence / Intermediate difficulty |
| 🔴 | High confidence / Advanced difficulty |
| ✔ | Positive indicator (a reason to keep digging) |
| ↓ | "then pivot to" |

---

> **Legal & scope.** This manual is for authorized defensive security operations, incident response, threat hunting, and education only. Nothing here is offensive tooling. Always operate within your rules of engagement and legal authority.

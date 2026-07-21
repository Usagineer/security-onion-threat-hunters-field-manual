# Contributing to the Field Manual

## Ground rules

- **Markdown is the source of truth.** Never hand-edit generated `.docx`/`.pdf`.
- **Every query must be validated** against a real Security Onion 2.x instance (or clearly marked `# UNVERIFIED` if it is a proposed query pending test).
- **One query per code block**, in a bare fenced block, so analysts can copy/paste directly.
- Keep the **hunt template** (`templates/hunt-template.md`) intact — consistency is the product.

## Adding a hunt

1. Copy `templates/hunt-template.md`.
2. Fill in every field. If you cannot fill in `Next Pivots`, the hunt is not finished.
3. Assign a **stable hunt number**. Numbers are never reused; new hunts append.
4. Set **Confidence** and **Difficulty** independently (see README).
5. Add the hunt to the phase file's mini table of contents.

## Confidence rubric

| Level | Meaning | Example |
|---|---|---|
| 🟢 Low | Often benign; needs corroboration | single RDP login, `whoami` |
| 🟡 Medium | Anomalous; worth a focused look | workstation initiating WinRM, Office → PowerShell |
| 🔴 High | Strong malicious signal on its own | `wsmprovhost.exe` → PowerShell after SMB, `PSEXESVC` service creation, `vssadmin delete shadows`, `sqlservr.exe` → `cmd.exe` |

## Field naming

Use ECS field names as surfaced in the Security Onion SOC **Hunt** UI. When a value is Zeek- or Suricata-specific, note the dataset (e.g. `event.dataset:zeek.dns`) so the reader knows where it comes from.

## Style

- Prefer verbs in step headers ("Group by", "Copy IP", "Pivot to").
- Use ✔ for positive indicators, and *Normal:* / *Suspicious:* for context.
- Keep prose tight. This is a field manual, not a textbook.

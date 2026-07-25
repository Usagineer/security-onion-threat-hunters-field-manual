# Phase 14 - Pivot Cheat Sheets

 **Analyst question:** What exact value should be pivoted next, and which detailed phase owns the resulting behavior?

## What this phase is for

Choose a fast, evidence-preserving next search after a common finding.

## What makes a result meaningful

A cheat sheet accelerates triage but does not replace the full phase methodology or corroboration.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Found Beaconing](../queries/phase-14-pivot-cheat-sheets/found-beaconing.md)

**Why use it:** Provides the next investigative pivots after finding Beaconing. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Found Dns](../queries/phase-14-pivot-cheat-sheets/found-dns.md)

**Why use it:** Provides the next investigative pivots after finding Dns. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Found Powershell](../queries/phase-14-pivot-cheat-sheets/found-powershell.md)

**Why use it:** Provides the next investigative pivots after finding Powershell. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Found Rdp](../queries/phase-14-pivot-cheat-sheets/found-rdp.md)

**Why use it:** Provides the next investigative pivots after finding Rdp. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Found Repeated Powershell](../queries/phase-14-pivot-cheat-sheets/found-repeated-powershell.md)

**Why use it:** Provides the next investigative pivots after finding Repeated Powershell. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Found Smb](../queries/phase-14-pivot-cheat-sheets/found-smb.md)

**Why use it:** Provides the next investigative pivots after finding Smb. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Found Suspicious Ip](../queries/phase-14-pivot-cheat-sheets/found-suspicious-ip.md)

**Why use it:** Provides the next investigative pivots after finding Suspicious Ip. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Found Telemetry Gap](../queries/phase-14-pivot-cheat-sheets/found-telemetry-gap.md)

**Why use it:** Provides the next investigative pivots after finding Telemetry Gap. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Found Winrm](../queries/phase-14-pivot-cheat-sheets/found-winrm.md)

**Why use it:** Provides the next investigative pivots after finding Winrm. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use the observed behavior as one step in a larger chain. Treat this query as the next focused move: identify the precise host, account, process, or infrastructure value, then continue into the detailed behavior phase that explains the objective.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

## Pivots and evidence preservation

Return to the linked behavior phase and document the pivot chain, conclusion, and outstanding questions.
Before deleting artifacts, disabling an account, or blocking traffic, preserve the relevant raw events, process or file metadata, timestamps, identifiers, and configuration. Include data that establishes direction and outcome, not only the alert that opened the case. If telemetry is absent, record the gap and use another data source rather than assuming no activity occurred.

## Common false positives

Approved administration, software deployment, monitoring, backup, security products, and maintenance can resemble attacker behavior. Verify the operator, signer, path, parent process, target population, and change record. A known tool used from an unexpected location, by an unexpected account, or in an unexpected sequence still needs investigation.

## Analyst handoff checklist

- [ ] Incident time range and timezone recorded.
- [ ] Original lead and each pivot value recorded.
- [ ] Source, target, account, process, and outcome identified where telemetry allows.
- [ ] Benign explanation validated or escalation rationale documented.
- [ ] Related hosts, accounts, indicators, and evidence-preservation needs scoped.

## Completion criteria

What exact value should be pivoted next, and which detailed phase owns the resulting behavior? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

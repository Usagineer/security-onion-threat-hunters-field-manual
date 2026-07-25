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

#### What this query is for

Use the **Found Beaconing** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Beaconing** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Found Dns](../queries/phase-14-pivot-cheat-sheets/found-dns.md)

#### What this query is for

Use the **Found Dns** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Dns** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Found Powershell](../queries/phase-14-pivot-cheat-sheets/found-powershell.md)

#### What this query is for

Use the **Found Powershell** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Powershell** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Found Rdp](../queries/phase-14-pivot-cheat-sheets/found-rdp.md)

#### What this query is for

Use the **Found Rdp** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Rdp** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Found Repeated Powershell](../queries/phase-14-pivot-cheat-sheets/found-repeated-powershell.md)

#### What this query is for

Use the **Found Repeated Powershell** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Repeated Powershell** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Found Smb](../queries/phase-14-pivot-cheat-sheets/found-smb.md)

#### What this query is for

Use the **Found Smb** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Smb** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Found Suspicious Ip](../queries/phase-14-pivot-cheat-sheets/found-suspicious-ip.md)

#### What this query is for

Use the **Found Suspicious Ip** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Suspicious Ip** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Found Telemetry Gap](../queries/phase-14-pivot-cheat-sheets/found-telemetry-gap.md)

#### What this query is for

Use the **Found Telemetry Gap** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Telemetry Gap** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Found Winrm](../queries/phase-14-pivot-cheat-sheets/found-winrm.md)

#### What this query is for

Use the **Found Winrm** query to choose the next focused pivot after a common finding. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Found Winrm** to advance one step in an attack chain by using the observed artifact to locate related accounts, systems, processes, or infrastructure. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

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

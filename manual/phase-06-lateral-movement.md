# Phase 6 - Lateral Movement

 **Analyst question:** Which source reached which target, under which identity and mechanism, and what executed on the target?

## What this phase is for

Map movement between systems using SMB, PsExec, WMI, WinRM, RDP, services, tasks, DCOM, and accounts.

## What makes a result meaningful

Remote administration is common; source role, target set, command, and timing distinguish normal work from spread.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [SMB](../queries/phase-06-lateral-movement/01-smb.md)

#### What this query is for

Use the **SMB** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **SMB** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Psexec](../queries/phase-06-lateral-movement/02-psexec.md)

#### What this query is for

Use the **Psexec** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Psexec** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [WMI](../queries/phase-06-lateral-movement/03-wmi.md)

#### What this query is for

Use the **WMI** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **WMI** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [WinRM](../queries/phase-06-lateral-movement/04-winrm.md)

#### What this query is for

Use the **WinRM** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **WinRM** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [RDP](../queries/phase-06-lateral-movement/05-rdp.md)

#### What this query is for

Use the **RDP** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **RDP** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Remote Services](../queries/phase-06-lateral-movement/06-remote-services.md)

#### What this query is for

Use the **Remote Services** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Remote Services** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Scheduled Tasks](../queries/phase-06-lateral-movement/07-scheduled-tasks.md)

#### What this query is for

Use the **Scheduled Tasks** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Scheduled Tasks** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [DCOM](../queries/phase-06-lateral-movement/08-dcom.md)

#### What this query is for

Use the **DCOM** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **DCOM** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Valid Account Spread](../queries/phase-06-lateral-movement/09-valid-account-spread.md)

#### What this query is for

Use the **Valid Account Spread** query to map remote access and execution between source and target systems. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Valid Account Spread** to use remote-management protocols or valid accounts to execute on a new host and expand their foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

## Pivots and evidence preservation

Use Phases 7, 8, 10, and 11 for target-side persistence, C2, execution, and identity evidence.
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

Which source reached which target, under which identity and mechanism, and what executed on the target? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

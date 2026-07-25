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

**Why use it:** Looks for lateral-movement behavior involving Smb. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Psexec](../queries/phase-06-lateral-movement/02-psexec.md)

**Why use it:** Looks for lateral-movement behavior involving Psexec. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [WMI](../queries/phase-06-lateral-movement/03-wmi.md)

**Why use it:** Looks for lateral-movement behavior involving Wmi. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [WinRM](../queries/phase-06-lateral-movement/04-winrm.md)

**Why use it:** Looks for lateral-movement behavior involving Winrm. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [RDP](../queries/phase-06-lateral-movement/05-rdp.md)

**Why use it:** Looks for lateral-movement behavior involving Rdp. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Remote Services](../queries/phase-06-lateral-movement/06-remote-services.md)

**Why use it:** Looks for lateral-movement behavior involving Remote Services. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Scheduled Tasks](../queries/phase-06-lateral-movement/07-scheduled-tasks.md)

**Why use it:** Looks for lateral-movement behavior involving Scheduled Tasks. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [DCOM](../queries/phase-06-lateral-movement/08-dcom.md)

**Why use it:** Looks for lateral-movement behavior involving Dcom. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Valid Account Spread](../queries/phase-06-lateral-movement/09-valid-account-spread.md)

**Why use it:** Looks for lateral-movement behavior involving Valid Account Spread. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may abuse this remote-management path to execute on a new host, copy tools, and extend their foothold. On the destination, look for a new process, persistence, outbound communications, and another source-to-target movement edge.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

# Phase 6 - Lateral Movement

 **Analyst question:** Which source reached which target, under which identity and mechanism, and what executed on the target?

## What this phase is for

Map movement between systems using SMB, PsExec, WMI, WinRM, RDP, services, tasks, DCOM, and accounts.

## Before you run a query

1. Set an absolute time range and note its timezone.
2. Write down the starting lead and the asset, account, or service ownership.
3. Replace all placeholders with case values; do not broaden searches until the first result is understood.
4. Save the result count and the values that become your next pivot.

## Investigation method

1. **Start narrow.** Use the file that matches the observed behavior, host, account, protocol, or indicator.
2. **Characterize the result.** Identify source, target, user, process, command line, time, and outcome.
3. **Corroborate.** Check an independent source such as endpoint, network, identity, DNS, TLS, or Suricata evidence.
4. **Compare with normal.** Validate role, approved tooling, maintenance windows, historical behavior, and clean peers.
5. **Scope and decide.** Search the same artifact or behavior across the estate, preserve evidence, and document a benign explanation or escalation rationale.

## What makes a result meaningful

Remote administration is common; source role, target set, command, and timing distinguish normal work from spread.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [01-smb](../queries/phase-06-lateral-movement/01-smb.md)
- [02-psexec](../queries/phase-06-lateral-movement/02-psexec.md)
- [03-wmi](../queries/phase-06-lateral-movement/03-wmi.md)
- [04-winrm](../queries/phase-06-lateral-movement/04-winrm.md)
- [05-rdp](../queries/phase-06-lateral-movement/05-rdp.md)
- [06-remote-services](../queries/phase-06-lateral-movement/06-remote-services.md)
- [07-scheduled-tasks](../queries/phase-06-lateral-movement/07-scheduled-tasks.md)
- [08-dcom](../queries/phase-06-lateral-movement/08-dcom.md)
- [09-valid-account-spread](../queries/phase-06-lateral-movement/09-valid-account-spread.md)

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

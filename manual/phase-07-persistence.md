# Phase 7 - Persistence

 **Analyst question:** How does the artifact persist, what payload does it run, and where else does it exist?

## What this phase is for

Find mechanisms that survive reboot, logoff, or cleanup, including tasks, services, WMI, BITS, autoruns, and cron.

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

The artifact configurationâ€”not its display name aloneâ€”shows whether it is durable and dangerous.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [01-registry-run-keys](../queries/phase-07-persistence/01-registry-run-keys.md)
- [02-startup-folder](../queries/phase-07-persistence/02-startup-folder.md)
- [03-services](../queries/phase-07-persistence/03-services.md)
- [04-wmi-events](../queries/phase-07-persistence/04-wmi-events.md)
- [05-scheduled-tasks](../queries/phase-07-persistence/05-scheduled-tasks.md)
- [06-bits-jobs](../queries/phase-07-persistence/06-bits-jobs.md)
- [07-com-hijacking](../queries/phase-07-persistence/07-com-hijacking.md)
- [08-linux-cron-and-temp-execution](../queries/phase-07-persistence/08-linux-cron-and-temp-execution.md)

## Pivots and evidence preservation

Use Phases 8 and 10 for payload behavior and Phase 6 to find deployment on peers.
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

How does the artifact persist, what payload does it run, and where else does it exist? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

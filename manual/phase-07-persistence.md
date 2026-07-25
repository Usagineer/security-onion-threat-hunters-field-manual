# Phase 7 - Persistence

 **Analyst question:** How does the artifact persist, what payload does it run, and where else does it exist?

## What this phase is for

Find mechanisms that survive reboot, logoff, or cleanup, including tasks, services, WMI, BITS, autoruns, and cron.

## What makes a result meaningful

The artifact configurationnot its display name aloneshows whether it is durable and dangerous.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Registry Run Keys](../queries/phase-07-persistence/01-registry-run-keys.md)

#### Attacker use and next pivot

An attacker may use this mechanism to restore access after reboot, logoff, or cleanup and to keep a payload available for later action. Pivot from the configured payload to its process ancestry, network connections, creation event, and copies on peer hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Startup Folder](../queries/phase-07-persistence/02-startup-folder.md)

#### Attacker use and next pivot

An attacker may use this mechanism to restore access after reboot, logoff, or cleanup and to keep a payload available for later action. Pivot from the configured payload to its process ancestry, network connections, creation event, and copies on peer hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Services](../queries/phase-07-persistence/03-services.md)

#### Attacker use and next pivot

An attacker may use this mechanism to restore access after reboot, logoff, or cleanup and to keep a payload available for later action. Pivot from the configured payload to its process ancestry, network connections, creation event, and copies on peer hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Wmi Events](../queries/phase-07-persistence/04-wmi-events.md)

#### Attacker use and next pivot

An attacker may use this mechanism to restore access after reboot, logoff, or cleanup and to keep a payload available for later action. Pivot from the configured payload to its process ancestry, network connections, creation event, and copies on peer hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Scheduled Tasks](../queries/phase-07-persistence/05-scheduled-tasks.md)

#### Attacker use and next pivot

An attacker may use this mechanism to restore access after reboot, logoff, or cleanup and to keep a payload available for later action. Pivot from the configured payload to its process ancestry, network connections, creation event, and copies on peer hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Bits Jobs](../queries/phase-07-persistence/06-bits-jobs.md)

#### Attacker use and next pivot

An attacker may use this mechanism to restore access after reboot, logoff, or cleanup and to keep a payload available for later action. Pivot from the configured payload to its process ancestry, network connections, creation event, and copies on peer hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Com Hijacking](../queries/phase-07-persistence/07-com-hijacking.md)

#### Attacker use and next pivot

An attacker may use this mechanism to restore access after reboot, logoff, or cleanup and to keep a payload available for later action. Pivot from the configured payload to its process ancestry, network connections, creation event, and copies on peer hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Linux Cron And Temp Execution](../queries/phase-07-persistence/08-linux-cron-and-temp-execution.md)

#### Attacker use and next pivot

An attacker may use this mechanism to restore access after reboot, logoff, or cleanup and to keep a payload available for later action. Pivot from the configured payload to its process ancestry, network connections, creation event, and copies on peer hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

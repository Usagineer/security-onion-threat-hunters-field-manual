# Phase 7 - Persistence

 **Analyst question:** How does the artifact persist, what payload does it run, and where else does it exist?

## What this phase is for

Find mechanisms that survive reboot, logoff, or cleanup, including tasks, services, WMI, BITS, autoruns, and cron.

## What makes a result meaningful

The artifact configurationnot its display name aloneshows whether it is durable and dangerous.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Registry Run Keys](../queries/security-onion/phase-07-persistence/01-registry-run-keys.md)

#### Why Hunt This

Hunt for **Registry Run Keys** because Run-key changes reveal programs configured to start at user logon. This query searches **event.code:13** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can place a payload in an autorun value. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which user hive is writable and when it executes. From **Registry Run Keys**, the likely next move is to relaunch malware and resume C2. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **payload execution and C2**, then verify the sequence with an independent telemetry source.

### [Startup Folder](../queries/security-onion/phase-07-persistence/02-startup-folder.md)

#### Why Hunt This

Hunt for **Startup Folder** because Startup-folder changes reveal user-logon persistence. This query searches **event.code:11** and organizes matches by **host.name file.name process.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can place a script, shortcut, or executable in a startup path. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which user and path trigger execution. From **Startup Folder**, the likely next move is to regain execution at logon. Analyst pivot: **host.name file.name process.name** into **payload execution and C2**, then verify the sequence with an independent telemetry source.

### [Services](../queries/security-onion/phase-07-persistence/03-services.md)

#### Why Hunt This

Hunt for **Services** because service installation reveals privileged boot-time or on-demand execution. This query searches **event.code:7045** and organizes matches by **host.name winlog.event_data.ServiceName winlog.event_data.ImagePath**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can register a payload as a Windows service. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account and binary path execute. From **Services**, the likely next move is to persist across reboot or run as SYSTEM. Analyst pivot: **host.name winlog.event_data.ServiceName winlog.event_data.ImagePath** into **payload execution and C2**, then verify the sequence with an independent telemetry source.

### [Wmi Events](../queries/security-onion/phase-07-persistence/04-wmi-events.md)

#### Why Hunt This

Hunt for **Wmi Events** because WMI activity can reveal remote process creation or event-triggered persistence. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can execute remotely or bind filters and consumers for durable execution. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts and event triggers accept WMI actions. From **Wmi Events**, the likely next move is to execute through WmiPrvSE or persist with subscriptions. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **payload execution and C2**, then verify the sequence with an independent telemetry source.

### [Scheduled Tasks](../queries/security-onion/phase-07-persistence/05-scheduled-tasks.md)

#### Why Hunt This

Hunt for **Scheduled Tasks** because task creation identifies code scheduled by time, event, logon, or remote action. This query searches **event.code:4698** and organizes matches by **host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can register a payload for one-time execution or persistence. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which task principal, trigger, and command execute. From **Scheduled Tasks**, the likely next move is to run later, after reboot, or on another host. Analyst pivot: **host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName** into **payload execution and C2**, then verify the sequence with an independent telemetry source.

### [Bits Jobs](../queries/security-onion/phase-07-persistence/06-bits-jobs.md)

#### Why Hunt This

Hunt for **Bits Jobs** because BITS activity reveals resilient background transfer and notification-command execution. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can download, upload, or launch content through trusted BITS components. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which URL, path, and job owner succeed. From **Bits Jobs**, the likely next move is to retrieve a stage, transfer data, or persist. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **payload execution and C2**, then verify the sequence with an independent telemetry source.

### [Com Hijacking](../queries/security-onion/phase-07-persistence/07-com-hijacking.md)

#### Why Hunt This

Hunt for **Com Hijacking** because COM registration changes can expose execution through a trusted application. This query searches **event.code:13** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can redirect a COM class to malicious code. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which trusted callers and writable registrations are available. From **Com Hijacking**, the likely next move is to inherit the caller context and persist. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **payload execution and C2**, then verify the sequence with an independent telemetry source.

### [Linux Cron And Temp Execution](../queries/security-onion/phase-07-persistence/08-linux-cron-and-temp-execution.md)

#### Why Hunt This

Hunt for **Linux Cron And Temp Execution** because cron entries reveal recurring Linux execution, especially from temporary paths. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can schedule scripts or payloads periodically or after reboot. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account, interpreter, and path execute. From **Linux Cron And Temp Execution**, the likely next move is to relaunch C2, collection, or transfer jobs. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **payload execution and C2**, then verify the sequence with an independent telemetry source.

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

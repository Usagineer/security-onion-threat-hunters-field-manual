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

#### Why Hunt This

Hunt for **SMB** because SMB connections, shares, and file operations reveal Windows file access and admin-share use. This query searches **event.dataset:zeek.conn, event.dataset:zeek.smb_mapping, event.dataset:zeek.smb_files, ports 445** and organizes matches by **source.ip destination.ip; source.ip destination.ip smb.share**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can enumerate shares, copy tools, collect data, or execute through administrative shares. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts expose shares and which accounts can write. From **SMB**, the likely next move is to stage a payload, create a service, or move laterally. Analyst pivot: **source.ip destination.ip; source.ip destination.ip smb.share** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

### [Psexec](../queries/phase-06-lateral-movement/02-psexec.md)

#### Why Hunt This

Hunt for **Psexec** because admin-share writes plus service creation form a recognizable PsExec execution chain. This query searches **event.dataset:zeek.dce_rpc, event.code:7045** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can copy a service binary and start it remotely with administrative credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which credentials and targets permit service execution. From **Psexec**, the likely next move is to run as SYSTEM and repeat movement. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

### [WMI](../queries/phase-06-lateral-movement/03-wmi.md)

#### Why Hunt This

Hunt for **WMI** because WMI activity can reveal remote process creation or event-triggered persistence. This query searches **event.dataset:zeek.conn, event.dataset:zeek.dce_rpc, ports 135** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can execute remotely or bind filters and consumers for durable execution. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts and event triggers accept WMI actions. From **WMI**, the likely next move is to execute through WmiPrvSE or persist with subscriptions. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

### [WinRM](../queries/phase-06-lateral-movement/04-winrm.md)

#### Why Hunt This

Hunt for **WinRM** because WinRM and wsmprovhost evidence identify remote PowerShell execution. This query searches **event.dataset:zeek.conn, ports 5985/5986** and organizes matches by **source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can run commands remotely through Windows management with valid credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts and accounts permit noninteractive administration. From **WinRM**, the likely next move is to deploy scripts, collect credentials, or continue movement. Analyst pivot: **source.ip destination.ip** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

### [RDP](../queries/phase-06-lateral-movement/05-rdp.md)

#### Why Hunt This

Hunt for **RDP** because RDP traffic and logons identify interactive Windows access, its account, source, target, and result. This query searches **event.dataset:zeek.conn, event.code:4624, event.code:4778, ports 3389** and organizes matches by **source.ip destination.ip; source.ip winlog.event_data.TargetUserName destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can authenticate with guessed, stolen, or reused credentials for an interactive desktop. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which Windows host and credential permit interactive access. From **RDP**, the likely next move is to run discovery, steal credentials, or establish persistence. Analyst pivot: **source.ip destination.ip; source.ip winlog.event_data.TargetUserName destination.ip** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

### [Remote Services](../queries/phase-06-lateral-movement/06-remote-services.md)

#### Why Hunt This

Hunt for **Remote Services** because remote service control connects authentication to destination-side execution. This query searches **event.dataset:zeek.dce_rpc, event.code:7045** and organizes matches by **host.name winlog.event_data.ServiceName winlog.event_data.ImagePath**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can create or modify a service to run a supplied binary with privilege. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which targets permit service control. From **Remote Services**, the likely next move is to execute as SYSTEM or establish persistence. Analyst pivot: **host.name winlog.event_data.ServiceName winlog.event_data.ImagePath** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

### [Scheduled Tasks](../queries/phase-06-lateral-movement/07-scheduled-tasks.md)

#### Why Hunt This

Hunt for **Scheduled Tasks** because task creation identifies code scheduled by time, event, logon, or remote action. This query searches **event.dataset:zeek.dce_rpc, event.code:4698** and organizes matches by **host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can register a payload for one-time execution or persistence. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which task principal, trigger, and command execute. From **Scheduled Tasks**, the likely next move is to run later, after reboot, or on another host. Analyst pivot: **host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

### [DCOM](../queries/phase-06-lateral-movement/08-dcom.md)

#### Why Hunt This

Hunt for **DCOM** because DCOM activity can reveal remote object activation used for lateral execution. This query searches **event.dataset:zeek.conn, event.dataset:zeek.dce_rpc, ports 135** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can instantiate remote COM objects through valid credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which systems expose DCOM and permit activation. From **DCOM**, the likely next move is to launch a target-side process and continue movement. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

### [Valid Account Spread](../queries/phase-06-lateral-movement/09-valid-account-spread.md)

#### Why Hunt This

Hunt for **Valid Account Spread** because one account authenticating broadly can expose credential reuse or lateral movement. This query searches **event.dataset:zeek.conn, event.code:4624, event.code:4625, ports 22/3389/445/5985/5986** and organizes matches by **source.ip host.name winlog.event_data.LogonType; destination.ip destination.port**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can quietly reuse a valid account across remote services. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned where the account works and what privilege it has. From **Valid Account Spread**, the likely next move is to expand to higher-value systems. Analyst pivot: **source.ip host.name winlog.event_data.LogonType; destination.ip destination.port** into **destination-side execution, persistence, and C2**, then verify the sequence with an independent telemetry source.

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

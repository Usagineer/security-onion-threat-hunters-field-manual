# Phase 11 - Active Directory and Windows Events

 **Analyst question:** Which identities, systems, and event sequence prove or rule out suspicious access and directory change?

## What this phase is for

Reconstruct authentication, privilege, account, process, Kerberos, task, and service activity.

## What makes a result meaningful

An event ID needs source, logon type, account role, target, and adjacent behavior to be useful.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Successful Logon](../queries/phase-11-active-directory/4624-successful-logon.md)

#### Why Hunt This

Hunt for **Successful Logon** because event 4624 records successful logon sessions and their account, source, type, and authentication. This query searches **event.code:4624** and organizes matches by **winlog.event_data.LogonType winlog.event_data.TargetUserName source.ip; source.ip winlog.event_data.TargetUserName host.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use valid credentials for network, interactive, service, or RDP sessions. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account works on which target. From **Successful Logon**, the likely next move is to launch processes, access resources, or move laterally. Analyst pivot: **winlog.event_data.LogonType winlog.event_data.TargetUserName source.ip; source.ip winlog.event_data.TargetUserName host.name** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Failed Logon](../queries/phase-11-active-directory/4625-failed-logon.md)

#### Why Hunt This

Hunt for **Failed Logon** because event 4625 records failed logons with account, source, status, and logon type. This query searches **event.code:4625** and organizes matches by **source.ip winlog.event_data.TargetUserName; winlog.event_data.TargetUserName host.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can guess, spray, validate, or test stolen credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which accounts exist and how controls respond. From **Failed Logon**, the likely next move is to refine the attack or follow a success. Analyst pivot: **source.ip winlog.event_data.TargetUserName; winlog.event_data.TargetUserName host.name** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Special Privileges](../queries/phase-11-active-directory/4672-special-privileges.md)

#### Why Hunt This

Hunt for **Special Privileges** because event 4672 identifies sensitive privileges assigned to a new logon. This query searches **event.code:4672** and organizes matches by **winlog.event_data.SubjectUserName host.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use an administrative identity for credential theft and system control. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which session carries powerful rights. From **Special Privileges**, the likely next move is to impair defenses, dump credentials, or persist. Analyst pivot: **winlog.event_data.SubjectUserName host.name** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Process Creation](../queries/phase-11-active-directory/4688-process-creation.md)

#### Why Hunt This

Hunt for **Process Creation** because event 4688 records process creation, ancestry, identity, and optionally command line. This query searches **event.code:4688** and organizes matches by **host.name winlog.event_data.NewProcessName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can start shells, scripts, tools, or masqueraded binaries. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which execution chain and privilege work. From **Process Creation**, the likely next move is to spawn payloads, persist, or contact C2. Analyst pivot: **host.name winlog.event_data.NewProcessName** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Scheduled Task Created](../queries/phase-11-active-directory/4698-scheduled-task-created.md)

#### Why Hunt This

Hunt for **Scheduled Task Created** because event 4698 records scheduled-task creation and task XML. This query searches **event.code:4698** and organizes matches by **host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can create a task for execution, movement, or persistence. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which principal, trigger, and command execute. From **Scheduled Task Created**, the likely next move is to run later or deploy remotely. Analyst pivot: **host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [User Account Created](../queries/phase-11-active-directory/4720-user-account-created.md)

#### Why Hunt This

Hunt for **User Account Created** because event 4720 identifies creation of a user account and its creator. This query searches **event.code:4720** and organizes matches by **host.name winlog.event_data.TargetUserName winlog.event_data.SubjectUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can create a backdoor identity for durable access. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account policies permit creation. From **User Account Created**, the likely next move is to grant groups and authenticate persistently. Analyst pivot: **host.name winlog.event_data.TargetUserName winlog.event_data.SubjectUserName** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Member Added Global Group](../queries/phase-11-active-directory/4728-member-added-global-group.md)

#### Why Hunt This

Hunt for **Member Added Global Group** because event 4728 records membership added to a global security group. This query searches **event.code:4728** and organizes matches by **winlog.event_data.TargetUserName winlog.event_data.MemberName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can grant a controlled identity broader domain rights. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which global group supplies useful privilege. From **Member Added Global Group**, the likely next move is to access protected systems or modify identities. Analyst pivot: **winlog.event_data.TargetUserName winlog.event_data.MemberName** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Member Added Local Group](../queries/phase-11-active-directory/4732-member-added-local-group.md)

#### Why Hunt This

Hunt for **Member Added Local Group** because event 4732 records membership added to a local security group. This query searches **event.code:4732** and organizes matches by **host.name winlog.event_data.TargetUserName winlog.event_data.MemberName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can grant a controlled account administrative rights on one system. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which local group permits management. From **Member Added Local Group**, the likely next move is to log on elevated, disable controls, or persist. Analyst pivot: **host.name winlog.event_data.TargetUserName winlog.event_data.MemberName** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Kerberos Tgt Requested](../queries/phase-11-active-directory/4768-kerberos-tgt-requested.md)

#### Why Hunt This

Hunt for **Kerberos Tgt Requested** because event 4768 records Kerberos TGT requests, client, encryption, and result. This query searches **event.code:4768** and organizes matches by **winlog.event_data.TargetUserName source.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can validate domain credentials and obtain a ticket-granting ticket. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account authenticates and which encryption applies. From **Kerberos Tgt Requested**, the likely next move is to request service tickets or reuse tickets. Analyst pivot: **winlog.event_data.TargetUserName source.ip** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Kerberos Service Ticket](../queries/phase-11-active-directory/4769-kerberos-service-ticket.md)

#### Why Hunt This

Hunt for **Kerberos Service Ticket** because event 4769 records service-ticket requests, SPN, client, and encryption. This query searches **event.code:4769** and organizes matches by **winlog.event_data.ServiceName winlog.event_data.TargetUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can access Kerberos services or collect tickets for Kerberoasting. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which SPNs and service accounts are useful. From **Kerberos Service Ticket**, the likely next move is to crack a ticket or access the service. Analyst pivot: **winlog.event_data.ServiceName winlog.event_data.TargetUserName** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Kerberos Preauth Failed](../queries/phase-11-active-directory/4771-kerberos-preauth-failed.md)

#### Why Hunt This

Hunt for **Kerberos Preauth Failed** because event 4771 records failed Kerberos preauthentication and failure context. This query searches **event.code:4771** and organizes matches by **winlog.event_data.TargetUserName source.ip; source.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can spray passwords or validate accounts through Kerberos. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which accounts exist and how preauthentication responds. From **Kerberos Preauth Failed**, the likely next move is to continue guessing or target weaker accounts. Analyst pivot: **winlog.event_data.TargetUserName source.ip; source.ip** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

### [Service Installed](../queries/phase-11-active-directory/7045-service-installed.md)

#### Why Hunt This

Hunt for **Service Installed** because service installation reveals privileged boot-time or on-demand execution. This query searches **event.code:7045** and organizes matches by **host.name winlog.event_data.ServiceName winlog.event_data.ImagePath**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can register a payload as a Windows service. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account and binary path execute. From **Service Installed**, the likely next move is to persist across reboot or run as SYSTEM. Analyst pivot: **host.name winlog.event_data.ServiceName winlog.event_data.ImagePath** into **the correlated identity and execution chain**, then verify the sequence with an independent telemetry source.

## Pivots and evidence preservation

Use Phases 5, 6, and 10 to corroborate identity events with credential, network, and execution evidence.
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

Which identities, systems, and event sequence prove or rule out suspicious access and directory change? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

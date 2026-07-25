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

**Why use it:** Reviews Windows and Active Directory event evidence involving Successful Logon. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Failed Logon](../queries/phase-11-active-directory/4625-failed-logon.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Failed Logon. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Special Privileges](../queries/phase-11-active-directory/4672-special-privileges.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Special Privileges. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Process Creation](../queries/phase-11-active-directory/4688-process-creation.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Process Creation. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Scheduled Task Created](../queries/phase-11-active-directory/4698-scheduled-task-created.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Scheduled Task Created. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [User Account Created](../queries/phase-11-active-directory/4720-user-account-created.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving User Account Created. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Member Added Global Group](../queries/phase-11-active-directory/4728-member-added-global-group.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Member Added Global Group. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Member Added Local Group](../queries/phase-11-active-directory/4732-member-added-local-group.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Member Added Local Group. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Kerberos Tgt Requested](../queries/phase-11-active-directory/4768-kerberos-tgt-requested.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Kerberos Tgt Requested. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Kerberos Service Ticket](../queries/phase-11-active-directory/4769-kerberos-service-ticket.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Kerberos Service Ticket. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Kerberos Preauth Failed](../queries/phase-11-active-directory/4771-kerberos-preauth-failed.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Kerberos Preauth Failed. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Service Installed](../queries/phase-11-active-directory/7045-service-installed.md)

**Why use it:** Reviews Windows and Active Directory event evidence involving Service Installed. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

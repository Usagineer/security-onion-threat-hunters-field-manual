# Phase 4 - Discovery

 **Analyst question:** What did the process or actor learn, and which discovered targets should be scoped next?

## What this phase is for

Identify reconnaissance of accounts, hosts, networks, sessions, processes, and services.

## What makes a result meaningful

A single administration command can be normal; a clustered sequence, unusual parent, or post-compromise timing is stronger.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Whoami](../queries/phase-04-discovery/01-whoami.md)

#### What this query is for

Use the **Whoami** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Whoami** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Hostname Ipconfig](../queries/phase-04-discovery/02-hostname-ipconfig.md)

#### What this query is for

Use the **Hostname Ipconfig** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Hostname Ipconfig** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Arp Route](../queries/phase-04-discovery/03-arp-route.md)

#### What this query is for

Use the **Arp Route** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Arp Route** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Systeminfo](../queries/phase-04-discovery/04-systeminfo.md)

#### What this query is for

Use the **Systeminfo** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Systeminfo** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Net User Group](../queries/phase-04-discovery/05-net-user-group.md)

#### What this query is for

Use the **Net User Group** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Net User Group** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Nltest](../queries/phase-04-discovery/06-nltest.md)

#### What this query is for

Use the **Nltest** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Nltest** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Netstat](../queries/phase-04-discovery/07-netstat.md)

#### What this query is for

Use the **Netstat** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Netstat** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Tasklist](../queries/phase-04-discovery/08-tasklist.md)

#### What this query is for

Use the **Tasklist** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Tasklist** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Quser Query User](../queries/phase-04-discovery/09-quser-query-user.md)

#### What this query is for

Use the **Quser Query User** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Quser Query User** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Powershell Discovery](../queries/phase-04-discovery/10-powershell-discovery.md)

#### What this query is for

Use the **Powershell Discovery** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Powershell Discovery** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Network Service Enumeration](../queries/phase-04-discovery/11-network-service-enumeration.md)

#### What this query is for

Use the **Network Service Enumeration** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Network Service Enumeration** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Icmp And Subnet Discovery](../queries/phase-04-discovery/12-icmp-and-subnet-discovery.md)

#### What this query is for

Use the **Icmp And Subnet Discovery** query to identify reconnaissance of users, hosts, routes, processes, and services. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Icmp And Subnet Discovery** to enumerate the environment to locate privileged identities, useful services, and high-value targets for credential theft or movement. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

## Pivots and evidence preservation

Use Phases 5 and 11 for identity targets, Phase 6 for remote services, and Phase 10 for execution.
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

What did the process or actor learn, and which discovered targets should be scoped next? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

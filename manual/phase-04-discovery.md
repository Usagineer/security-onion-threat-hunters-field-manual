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

**Why use it:** Looks for host or network discovery activity involving Whoami. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Hostname Ipconfig](../queries/phase-04-discovery/02-hostname-ipconfig.md)

**Why use it:** Looks for host or network discovery activity involving Hostname Ipconfig. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Arp Route](../queries/phase-04-discovery/03-arp-route.md)

**Why use it:** Looks for host or network discovery activity involving Arp Route. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Systeminfo](../queries/phase-04-discovery/04-systeminfo.md)

**Why use it:** Looks for host or network discovery activity involving Systeminfo. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Net User Group](../queries/phase-04-discovery/05-net-user-group.md)

**Why use it:** Looks for host or network discovery activity involving Net User Group. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Nltest](../queries/phase-04-discovery/06-nltest.md)

**Why use it:** Looks for host or network discovery activity involving Nltest. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Netstat](../queries/phase-04-discovery/07-netstat.md)

**Why use it:** Looks for host or network discovery activity involving Netstat. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Tasklist](../queries/phase-04-discovery/08-tasklist.md)

**Why use it:** Looks for host or network discovery activity involving Tasklist. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Quser Query User](../queries/phase-04-discovery/09-quser-query-user.md)

**Why use it:** Looks for host or network discovery activity involving Quser Query User. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Powershell Discovery](../queries/phase-04-discovery/10-powershell-discovery.md)

**Why use it:** Looks for host or network discovery activity involving Powershell Discovery. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Network Service Enumeration](../queries/phase-04-discovery/11-network-service-enumeration.md)

**Why use it:** Looks for host or network discovery activity involving Network Service Enumeration. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Icmp And Subnet Discovery](../queries/phase-04-discovery/12-icmp-and-subnet-discovery.md)

**Why use it:** Looks for host or network discovery activity involving Icmp And Subnet Discovery. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this discovery activity to identify privileged accounts, domain controllers, shares, remote services, and high-value targets. The next position is often credential access or lateral movement to a discovered system.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

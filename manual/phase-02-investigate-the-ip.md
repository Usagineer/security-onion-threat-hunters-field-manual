# Phase 2 - Investigate the Suspicious IP

 **Analyst question:** Which internal systems communicated with this IP, what did they do, and does the evidence support an incident?

## What this phase is for

Build a complete, IP-centered evidence picture from a network alert, IOC, or analyst lead.

## What makes a result meaningful

A rare address alone is weak. Confidence rises when DNS, protocol logs, alerts, and endpoint telemetry describe the same activity.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Everything](../queries/phase-02-investigate-the-ip/00-everything.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [SMB](../queries/phase-02-investigate-the-ip/01-smb.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [RDP](../queries/phase-02-investigate-the-ip/02-rdp.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [WinRM](../queries/phase-02-investigate-the-ip/03-winrm.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [DNS](../queries/phase-02-investigate-the-ip/04-dns.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [HTTP](../queries/phase-02-investigate-the-ip/05-http.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [TLS](../queries/phase-02-investigate-the-ip/06-tls.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Suricata](../queries/phase-02-investigate-the-ip/07-suricata.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Endpoint](../queries/phase-02-investigate-the-ip/08-endpoint.md)

#### Attacker use and next pivot

An attacker may use the identified IP as command infrastructure, a staging location, or a route to another system. After contact, look for DNS or TLS context, the endpoint process behind the connection, and activity on every other host that used the same destination.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

## Pivots and evidence preservation

Pivot to Phases 3, 6, 8, 9, and 10 according to the observed behavior.
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

Which internal systems communicated with this IP, what did they do, and does the evidence support an incident? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

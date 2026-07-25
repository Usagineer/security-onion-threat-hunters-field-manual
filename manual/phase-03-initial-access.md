# Phase 3 - Initial Access

 **Analyst question:** What is the earliest defensible entry event, and what evidence connects it to execution on the affected system?

## What this phase is for

Determine how an actor first entered through remote access, public services, email, or user delivery.

## What makes a result meaningful

Build a delivery or login chain rather than trusting a successful authentication event by itself.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [RDP](../queries/phase-03-initial-access/01-rdp.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [VPN](../queries/phase-03-initial-access/02-vpn.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [SSH](../queries/phase-03-initial-access/03-ssh.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Web Attacks](../queries/phase-03-initial-access/04-web-attacks.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [SMB](../queries/phase-03-initial-access/05-smb.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [MSSQL](../queries/phase-03-initial-access/06-mssql.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [FTP](../queries/phase-03-initial-access/07-ftp.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Email](../queries/phase-03-initial-access/08-email.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Phishing](../queries/phase-03-initial-access/09-phishing.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Drive By Downloads](../queries/phase-03-initial-access/10-drive-by-downloads.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Web Shell And Server Side Rce](../queries/phase-03-initial-access/11-web-shell-and-server-side-rce.md)

#### Attacker use and next pivot

An attacker may abuse this access path to gain an initial foothold with stolen credentials, an exposed service, or user-delivered content. After success, expect process execution, host and account discovery, and attempts to establish durable access.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

## Pivots and evidence preservation

Use Phases 4, 6, 10, and 11 to scope activity that follows entry.
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

What is the earliest defensible entry event, and what evidence connects it to execution on the affected system? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

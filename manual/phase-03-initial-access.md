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

#### What this query is for

Use the **RDP** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **RDP** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [VPN](../queries/phase-03-initial-access/02-vpn.md)

#### What this query is for

Use the **VPN** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **VPN** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [SSH](../queries/phase-03-initial-access/03-ssh.md)

#### What this query is for

Use the **SSH** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **SSH** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Web Attacks](../queries/phase-03-initial-access/04-web-attacks.md)

#### What this query is for

Use the **Web Attacks** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **Web Attacks** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [SMB](../queries/phase-03-initial-access/05-smb.md)

#### What this query is for

Use the **SMB** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **SMB** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [MSSQL](../queries/phase-03-initial-access/06-mssql.md)

#### What this query is for

Use the **MSSQL** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **MSSQL** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [FTP](../queries/phase-03-initial-access/07-ftp.md)

#### What this query is for

Use the **FTP** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **FTP** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Email](../queries/phase-03-initial-access/08-email.md)

#### What this query is for

Use the **Email** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **Email** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Phishing](../queries/phase-03-initial-access/09-phishing.md)

#### What this query is for

Use the **Phishing** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **Phishing** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Drive By Downloads](../queries/phase-03-initial-access/10-drive-by-downloads.md)

#### What this query is for

Use the **Drive By Downloads** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **Drive By Downloads** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Web Shell And Server Side Rce](../queries/phase-03-initial-access/11-web-shell-and-server-side-rce.md)

#### What this query is for

Use the **Web Shell And Server Side Rce** query to establish how access was gained through an exposed service, remote access path, or user delivery. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may use **Web Shell And Server Side Rce** to take advantage of an exposed or weakly protected service, or use stolen credentials or social engineering, to gain an initial foothold. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

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

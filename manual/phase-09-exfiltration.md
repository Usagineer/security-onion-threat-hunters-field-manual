# Phase 9 - Exfiltration

 **Analyst question:** Was sensitive data collected, staged, or transmitted; by whom, to where, and with what evidence?

## What this phase is for

Investigate collection, staging, compression, and outbound transfer through protocols and cloud services.

## What makes a result meaningful

Large transfers may be backup or synchronization; correlate with archive creation, exports, identity, and destination ownership.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [FTP](../queries/phase-09-exfiltration/01-ftp.md)

#### What this query is for

Use the **FTP** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **FTP** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [SFTP](../queries/phase-09-exfiltration/02-sftp.md)

#### What this query is for

Use the **SFTP** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **SFTP** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [SCP](../queries/phase-09-exfiltration/03-scp.md)

#### What this query is for

Use the **SCP** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **SCP** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Cloud Storage](../queries/phase-09-exfiltration/04-cloud-storage.md)

#### What this query is for

Use the **Cloud Storage** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Cloud Storage** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Onedrive](../queries/phase-09-exfiltration/05-onedrive.md)

#### What this query is for

Use the **Onedrive** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Onedrive** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Dropbox](../queries/phase-09-exfiltration/06-dropbox.md)

#### What this query is for

Use the **Dropbox** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Dropbox** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Mega](../queries/phase-09-exfiltration/07-mega.md)

#### What this query is for

Use the **Mega** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Mega** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Google Drive](../queries/phase-09-exfiltration/08-google-drive.md)

#### What this query is for

Use the **Google Drive** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Google Drive** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Large Uploads](../queries/phase-09-exfiltration/09-large-uploads.md)

#### What this query is for

Use the **Large Uploads** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Large Uploads** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Archive Creation](../queries/phase-09-exfiltration/10-archive-creation.md)

#### What this query is for

Use the **Archive Creation** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Archive Creation** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Database Collection](../queries/phase-09-exfiltration/11-database-collection.md)

#### What this query is for

Use the **Database Collection** query to assess data collection, staging, and outbound transfer. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Database Collection** to collect and stage data before transferring it to external infrastructure or a cloud service. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

## Pivots and evidence preservation

Use Phase 8 for the channel and Phase 10 for the collection or transfer process.
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

Was sensitive data collected, staged, or transmitted; by whom, to where, and with what evidence? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

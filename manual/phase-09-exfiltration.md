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

**Why use it:** Looks for collection or exfiltration behavior involving Ftp. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [SFTP](../queries/phase-09-exfiltration/02-sftp.md)

**Why use it:** Looks for collection or exfiltration behavior involving Sftp. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [SCP](../queries/phase-09-exfiltration/03-scp.md)

**Why use it:** Looks for collection or exfiltration behavior involving Scp. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Cloud Storage](../queries/phase-09-exfiltration/04-cloud-storage.md)

**Why use it:** Looks for collection or exfiltration behavior involving Cloud Storage. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Onedrive](../queries/phase-09-exfiltration/05-onedrive.md)

**Why use it:** Looks for collection or exfiltration behavior involving Onedrive. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Dropbox](../queries/phase-09-exfiltration/06-dropbox.md)

**Why use it:** Looks for collection or exfiltration behavior involving Dropbox. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Mega](../queries/phase-09-exfiltration/07-mega.md)

**Why use it:** Looks for collection or exfiltration behavior involving Mega. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Google Drive](../queries/phase-09-exfiltration/08-google-drive.md)

**Why use it:** Looks for collection or exfiltration behavior involving Google Drive. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Large Uploads](../queries/phase-09-exfiltration/09-large-uploads.md)

**Why use it:** Looks for collection or exfiltration behavior involving Large Uploads. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Archive Creation](../queries/phase-09-exfiltration/10-archive-creation.md)

**Why use it:** Looks for collection or exfiltration behavior involving Archive Creation. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Database Collection](../queries/phase-09-exfiltration/11-database-collection.md)

**Why use it:** Looks for collection or exfiltration behavior involving Database Collection. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

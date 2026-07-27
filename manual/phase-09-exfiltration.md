# Phase 9 - Exfiltration

 **Analyst question:** Was sensitive data collected, staged, or transmitted; by whom, to where, and with what evidence?

## What this phase is for

Investigate collection, staging, compression, and outbound transfer through protocols and cloud services.

## What makes a result meaningful

Large transfers may be backup or synchronization; correlate with archive creation, exports, identity, and destination ownership.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [FTP](../queries/security-onion/phase-09-exfiltration/01-ftp.md)

#### Why Hunt This

Hunt for **FTP** because FTP records reveal legacy file transfer, authentication, and unusual endpoints. This query searches **event.dataset:zeek.conn, event.dataset:zeek.ftp, ports 21** and organizes matches by **source.ip destination.ip; source.ip destination.ip ftp.arg**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can deliver payloads or exfiltrate data, sometimes with exposed credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which server accepts files and which credentials work. From **FTP**, the likely next move is to upload tooling, retrieve staged data, or switch to SFTP. Analyst pivot: **source.ip destination.ip; source.ip destination.ip ftp.arg** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [SFTP](../queries/security-onion/phase-09-exfiltration/02-sftp.md)

#### Why Hunt This

Hunt for **SFTP** because SFTP evidence identifies encrypted file transfer over SSH. This query searches **event.dataset:zeek.conn, event.dataset:zeek.ssh, ports 22** and organizes matches by **source.ip destination.ip; source.ip destination.ip ssh.client**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use valid SSH credentials to import tools or export data while content stays encrypted. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account and endpoint support file transfer. From **SFTP**, the likely next move is to repeat transfers or establish an interactive SSH session. Analyst pivot: **source.ip destination.ip; source.ip destination.ip ssh.client** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [SCP](../queries/security-onion/phase-09-exfiltration/03-scp.md)

#### Why Hunt This

Hunt for **SCP** because SCP evidence identifies direct file copies over SSH. This query searches **event.dataset:zeek.conn, ports 22** and organizes matches by **source.ip destination.ip source.bytes**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use stolen SSH credentials to import tools or export archives. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account can copy which local and remote paths. From **SCP**, the likely next move is to execute the tool or move more collected data. Analyst pivot: **source.ip destination.ip source.bytes** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [Cloud Storage](../queries/security-onion/phase-09-exfiltration/04-cloud-storage.md)

#### Why Hunt This

Hunt for **Cloud Storage** because cloud-storage uploads can expose trusted services used for unauthorized transfer. This query searches **event.dataset:zeek.ssl, event.dataset:zeek.dns** and organizes matches by **source.ip tls.client.server_name; source.ip dns.question.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can blend exfiltration into commonly allowed HTTPS providers. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which provider and account accept uploads. From **Cloud Storage**, the likely next move is to move staged data or switch providers. Analyst pivot: **source.ip tls.client.server_name; source.ip dns.question.name** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [Onedrive](../queries/security-onion/phase-09-exfiltration/05-onedrive.md)

#### Why Hunt This

Hunt for **Onedrive** because OneDrive activity can identify data movement through Microsoft cloud storage. This query searches **event.dataset:zeek.ssl, event.dataset:zeek.conn** and organizes matches by **source.ip tls.client.server_name; source.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can abuse a Microsoft account or sync client to upload collected files. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which tenant, identity, and folders receive data. From **Onedrive**, the likely next move is to share or retrieve files externally. Analyst pivot: **source.ip tls.client.server_name; source.ip** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [Dropbox](../queries/security-onion/phase-09-exfiltration/06-dropbox.md)

#### Why Hunt This

Hunt for **Dropbox** because Dropbox activity can expose transfers to personal or attacker-controlled storage. This query searches **event.dataset:zeek.ssl, event.dataset:zeek.dns** and organizes matches by **source.ip tls.client.server_name; source.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use Dropbox clients or APIs over trusted HTTPS. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which account or token accepts uploads. From **Dropbox**, the likely next move is to retrieve data or automate more uploads. Analyst pivot: **source.ip tls.client.server_name; source.ip** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [Mega](../queries/security-onion/phase-09-exfiltration/07-mega.md)

#### Why Hunt This

Hunt for **Mega** because MEGA traffic can identify uncommon encrypted cloud-storage transfer. This query searches **event.dataset:zeek.ssl** and organizes matches by **source.ip tls.client.server_name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use MEGA clients or APIs for encrypted archive transfer. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which process and account can upload. From **Mega**, the likely next move is to move more archives or stage tools. Analyst pivot: **source.ip tls.client.server_name** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [Google Drive](../queries/security-onion/phase-09-exfiltration/08-google-drive.md)

#### Why Hunt This

Hunt for **Google Drive** because Google Drive activity can expose upload to consumer or attacker-controlled accounts. This query searches **event.dataset:zeek.ssl, event.dataset:zeek.conn** and organizes matches by **source.ip tls.client.server_name; source.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use OAuth, browsers, or sync tools for trusted-service exfiltration. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which user, token, and process perform uploads. From **Google Drive**, the likely next move is to share the files or continue synchronized collection. Analyst pivot: **source.ip tls.client.server_name; source.ip** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [Large Uploads](../queries/security-onion/phase-09-exfiltration/09-large-uploads.md)

#### Why Hunt This

Hunt for **Large Uploads** because high outbound byte counts identify candidate bulk transfer. This query searches **event.dataset:zeek.conn** and organizes matches by **source.ip destination.ip; source.ip destination.as.organization.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can send archives or exports in large or threshold-avoiding chunks. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which host, destination, and transfer size succeed. From **Large Uploads**, the likely next move is to complete exfiltration or switch to a quieter channel. Analyst pivot: **source.ip destination.ip; source.ip destination.as.organization.name** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [Archive Creation](../queries/security-onion/phase-09-exfiltration/10-archive-creation.md)

#### Why Hunt This

Hunt for **Archive Creation** because archive creation can reveal staging before transfer. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **host.name process.name file.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can compress and optionally encrypt collected files. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which paths are readable and where staging is possible. From **Archive Creation**, the likely next move is to upload the archive and remove staging evidence. Analyst pivot: **host.name process.name file.name** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

### [Database Collection](../queries/security-onion/phase-09-exfiltration/11-database-collection.md)

#### Why Hunt This

Hunt for **Database Collection** because database dump and export activity can expose bulk structured-data collection. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **host.name user.name process.name process.command_line**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use native tools to export valuable tables efficiently. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which databases, credentials, and staging paths are available. From **Database Collection**, the likely next move is to compress and exfiltrate the dump. Analyst pivot: **host.name user.name process.name process.command_line** into **collection, staging, and transfer evidence**, then verify the sequence with an independent telemetry source.

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

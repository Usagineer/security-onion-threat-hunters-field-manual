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

#### Why Hunt This

Hunt for **RDP** because RDP traffic and logons identify interactive Windows access, its account, source, target, and result. This query searches **event.dataset:zeek.conn, event.code:4625, ports 3389** and organizes matches by **source.ip destination.ip; source.ip winlog.event_data.TargetUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can authenticate with guessed, stolen, or reused credentials for an interactive desktop. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which Windows host and credential permit interactive access. From **RDP**, the likely next move is to run discovery, steal credentials, or establish persistence. Analyst pivot: **source.ip destination.ip; source.ip winlog.event_data.TargetUserName** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [VPN](../queries/phase-03-initial-access/02-vpn.md)

#### Why Hunt This

Hunt for **VPN** because VPN connection and authentication records identify entry through a trusted remote-access gateway. This query searches **event.dataset:zeek.conn, event.module:suricata** and organizes matches by **source.ip destination.ip; source.ip source.geo.country_name user.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use stolen credentials, session tokens, weak MFA, or an exposed appliance. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which identity and source pass remote-access controls. From **VPN**, the likely next move is to enumerate internal routes and access managed endpoints. Analyst pivot: **source.ip destination.ip; source.ip source.geo.country_name user.name** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [SSH](../queries/phase-03-initial-access/03-ssh.md)

#### Why Hunt This

Hunt for **SSH** because SSH records identify encrypted shell access, client software, authentication, and unusual targets. This query searches **event.dataset:zeek.conn, event.dataset:zeek.ssh, ports 22** and organizes matches by **source.ip destination.ip; source.ip destination.ip ssh.auth.success**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can reuse keys or passwords for shells, tunneling, and file transfer. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which Unix-like hosts accept authentication and forwarding. From **SSH**, the likely next move is to add keys, transfer tools, or tunnel to another subnet. Analyst pivot: **source.ip destination.ip; source.ip destination.ip ssh.auth.success** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [Web Attacks](../queries/phase-03-initial-access/04-web-attacks.md)

#### Why Hunt This

Hunt for **Web Attacks** because HTTP methods, paths, results, and signatures can expose exploitation attempts. This query searches **event.dataset:zeek.http, event.module:suricata** and organizes matches by **rule.name source.ip destination.ip; source.ip url.original**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can exploit injection, traversal, deserialization, upload, or authentication flaws. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which endpoint and payload cross the application boundary. From **Web Attacks**, the likely next move is to execute code, steal data, or write a web shell. Analyst pivot: **rule.name source.ip destination.ip; source.ip url.original** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [SMB](../queries/phase-03-initial-access/05-smb.md)

#### Why Hunt This

Hunt for **SMB** because SMB connections, shares, and file operations reveal Windows file access and admin-share use. This query searches **event.dataset:zeek.conn, event.dataset:zeek.smb_mapping, event.module:suricata, ports 445** and organizes matches by **source.ip destination.ip smb.share**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can enumerate shares, copy tools, collect data, or execute through administrative shares. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts expose shares and which accounts can write. From **SMB**, the likely next move is to stage a payload, create a service, or move laterally. Analyst pivot: **source.ip destination.ip smb.share** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [MSSQL](../queries/phase-03-initial-access/06-mssql.md)

#### Why Hunt This

Hunt for **MSSQL** because database connections and command-shell behavior can expose database and host compromise. This query searches **event.dataset:zeek.conn, ports 1433** and organizes matches by **source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can steal database credentials or enable command features such as xp_cmdshell. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which database accepts access and whether its service can run OS commands. From **MSSQL**, the likely next move is to dump data, execute payloads, or pivot from the database host. Analyst pivot: **source.ip destination.ip** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [FTP](../queries/phase-03-initial-access/07-ftp.md)

#### Why Hunt This

Hunt for **FTP** because FTP records reveal legacy file transfer, authentication, and unusual endpoints. This query searches **event.dataset:zeek.conn, event.dataset:zeek.ftp, ports 21** and organizes matches by **source.ip destination.ip ftp.command ftp.reply_code; source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can deliver payloads or exfiltrate data, sometimes with exposed credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which server accepts files and which credentials work. From **FTP**, the likely next move is to upload tooling, retrieve staged data, or switch to SFTP. Analyst pivot: **source.ip destination.ip ftp.command ftp.reply_code; source.ip destination.ip** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [Email](../queries/phase-03-initial-access/08-email.md)

#### Why Hunt This

Hunt for **Email** because mail metadata connects a delivered message, sender, recipient, attachment, and URL. This query searches **event.dataset:zeek.smtp, event.dataset:zeek.files** and organizes matches by **source.ip destination.ip smtp.mailfrom smtp.rcptto; smtp.mailfrom smtp.subject**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can deliver malicious links, attachments, or conversation hijacks. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which recipient and content bypass filtering. From **Email**, the likely next move is to trigger execution, capture credentials, or target related users. Analyst pivot: **source.ip destination.ip smtp.mailfrom smtp.rcptto; smtp.mailfrom smtp.subject** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [Phishing](../queries/phase-03-initial-access/09-phishing.md)

#### Why Hunt This

Hunt for **Phishing** because phishing evidence connects social engineering to clicks, credential entry, or execution. This query searches **event.dataset:zeek.http, event.dataset:zeek.files** and organizes matches by **source.ip destination.ip file.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can impersonate a trusted sender to obtain credentials or user execution. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which lure, identity, and delivery path succeed. From **Phishing**, the likely next move is to reuse credentials or deploy a payload. Analyst pivot: **source.ip destination.ip file.name** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [Drive By Downloads](../queries/phase-03-initial-access/10-drive-by-downloads.md)

#### Why Hunt This

Hunt for **Drive By Downloads** because browser downloads and execution can expose compromise caused by a visited or redirected page. This query searches **event.dataset:zeek.files, event.dataset:zeek.http, event.module:suricata** and organizes matches by **source.ip destination.ip file.name; url.domain url.original**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can compromise a site or advertisement to deliver an exploit or payload. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which browser and user reach the delivery chain. From **Drive By Downloads**, the likely next move is to launch a payload, establish C2, or persist. Analyst pivot: **source.ip destination.ip file.name; url.domain url.original** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

### [Web Shell And Server Side Rce](../queries/phase-03-initial-access/11-web-shell-and-server-side-rce.md)

#### Why Hunt This

Hunt for **Web Shell And Server Side Rce** because web-server child processes and commands can prove server-side execution. This query searches **event.dataset:zeek.http** and organizes matches by **source.ip destination.ip url.original http.response.status_code**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can exploit an application or upload a script that runs as the web-service identity. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which application path executes code and what privileges it has. From **Web Shell And Server Side Rce**, the likely next move is to persist with a web shell or pivot to databases and internal services. Analyst pivot: **source.ip destination.ip url.original http.response.status_code** into **execution, discovery, credential access, and persistence**, then verify the sequence with an independent telemetry source.

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

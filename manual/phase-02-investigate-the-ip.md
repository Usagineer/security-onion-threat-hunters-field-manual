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

#### Why Hunt This

Hunt for **Everything** because a broad IP pivot establishes every dataset, direction, and protocol tied to the address. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **network.protocol destination.port; event.dataset**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use one address for delivery, C2, scanning, redirection, or transfer. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts and protocols communicate with the address. From **Everything**, the likely next move is to pivot to the endpoint process and behavior-specific phase. Analyst pivot: **network.protocol destination.port; event.dataset** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

### [SMB](../queries/phase-02-investigate-the-ip/01-smb.md)

#### Why Hunt This

Hunt for **SMB** because SMB connections, shares, and file operations reveal Windows file access and admin-share use. This query searches **event.dataset:zeek.smb_mapping, event.dataset:zeek.smb_files, event.dataset:zeek.dce_rpc** and organizes matches by **smb.share; file.name file.path**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can enumerate shares, copy tools, collect data, or execute through administrative shares. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts expose shares and which accounts can write. From **SMB**, the likely next move is to stage a payload, create a service, or move laterally. Analyst pivot: **smb.share; file.name file.path** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

### [RDP](../queries/phase-02-investigate-the-ip/02-rdp.md)

#### Why Hunt This

Hunt for **RDP** because RDP traffic and logons identify interactive Windows access, its account, source, target, and result. This query searches **event.dataset:zeek.conn, event.dataset:zeek.rdp, event.code:4624, ports 3389** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can authenticate with guessed, stolen, or reused credentials for an interactive desktop. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which Windows host and credential permit interactive access. From **RDP**, the likely next move is to run discovery, steal credentials, or establish persistence. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

### [WinRM](../queries/phase-02-investigate-the-ip/03-winrm.md)

#### Why Hunt This

Hunt for **WinRM** because WinRM and wsmprovhost evidence identify remote PowerShell execution. This query searches **event.dataset:zeek.conn, event.dataset:zeek.http, ports 5985/5986** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can run commands remotely through Windows management with valid credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts and accounts permit noninteractive administration. From **WinRM**, the likely next move is to deploy scripts, collect credentials, or continue movement. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

### [DNS](../queries/phase-02-investigate-the-ip/04-dns.md)

#### Why Hunt This

Hunt for **DNS** because DNS evidence links queried names, answers, clients, and subsequent connections. This query searches **event.dataset:zeek.dns** and organizes matches by **dns.question.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can resolve delivery or C2 infrastructure, use dynamic answers, or bypass approved resolvers. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which host queried which name and which address it received. From **DNS**, the likely next move is to connect to the answer, rotate infrastructure, or tunnel through DNS. Analyst pivot: **dns.question.name** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

### [HTTP](../queries/phase-02-investigate-the-ip/05-http.md)

#### Why Hunt This

Hunt for **HTTP** because HTTP metadata exposes methods, hosts, paths, agents, status, and transfer direction. This query searches **event.dataset:zeek.http** and organizes matches by **url.domain http.request.method; user_agent.original**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can deliver payloads, receive commands, or transfer data through web protocols. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which URI, client, and server complete the exchange. From **HTTP**, the likely next move is to retrieve content, post results, or switch to TLS. Analyst pivot: **url.domain http.request.method; user_agent.original** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

### [TLS](../queries/phase-02-investigate-the-ip/06-tls.md)

#### Why Hunt This

Hunt for **TLS** because TLS metadata reveals SNI, certificates, versions, fingerprints, and encrypted session outcomes. This query searches **event.dataset:zeek.ssl, event.dataset:zeek.x509** and organizes matches by **tls.client.server_name; tls.client.ja3 tls.server.ja3s**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can hide delivery or C2 content inside encryption while leaking handshake metadata. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which names, certificates, and clients identify the encrypted channel. From **TLS**, the likely next move is to cluster related hosts or pivot to the responsible endpoint process. Analyst pivot: **tls.client.server_name; tls.client.ja3 tls.server.ja3s** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

### [Suricata](../queries/phase-02-investigate-the-ip/07-suricata.md)

#### Why Hunt This

Hunt for **Suricata** because signature alerts can identify exploit delivery, malware, policy violations, or C2. This query searches **event.module:suricata** and organizes matches by **rule.name rule.category**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can send known exploit or malware traffic that matches a network signature. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which flow triggered and whether communication succeeded. From **Suricata**, the likely next move is to pivot through community ID to protocol and endpoint evidence. Analyst pivot: **rule.name rule.category** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

### [Endpoint](../queries/phase-02-investigate-the-ip/08-endpoint.md)

#### Why Hunt This

Hunt for **Endpoint** because endpoint network and process records identify the executable and user behind a connection. This query searches **event.module:endpoint** and organizes matches by **process.name destination.ip destination.port; process.name process.parent.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can run network activity from a payload, script, or abused trusted process. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which process, parent, user, and host own the traffic. From **Endpoint**, the likely next move is to trace ancestry, files, persistence, and follow-on execution. Analyst pivot: **process.name destination.ip destination.port; process.name process.parent.name** into **endpoint ownership and the behavior-specific phase**, then verify the sequence with an independent telemetry source.

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

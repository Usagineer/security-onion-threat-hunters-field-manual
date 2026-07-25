# Phase 8 - Command and Control

 **Analyst question:** What process communicates with which infrastructure, how regularly, and why is it normal or suspicious?

## What this phase is for

Assess beaconing, DNS tunneling, TLS, HTTP, proxies, and tunnels used for operator communication.

## What makes a result meaningful

Regular timing alone is not C2; stack timing, infrastructure rarity, process ancestry, and protocol details.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Beaconing](../queries/phase-08-command-and-control/01-beaconing.md)

#### Why Hunt This

Hunt for **Beaconing** because repeated low-variance connections can reveal an automated implant calling home. This query searches **event.dataset:zeek.conn** and organizes matches by **source.ip destination.ip; network.bytes destination.port**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can poll C2 at fixed or jittered intervals while generating little traffic. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts are infected and how reliably C2 is reachable. From **Beaconing**, the likely next move is to deliver tasks, change timing, or move to backup C2. Analyst pivot: **source.ip destination.ip; network.bytes destination.port** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

### [Dns Tunneling](../queries/phase-08-command-and-control/02-dns-tunneling.md)

#### Why Hunt This

Hunt for **Dns Tunneling** because long or encoded DNS labels can reveal commands or data hidden in name resolution. This query searches **event.dataset:zeek.dns** and organizes matches by **dns.question.name; source.ip dns.question.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can encode commands or stolen data in DNS questions and answers. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which resolver path and controlled domain carry the tunnel. From **Dns Tunneling**, the likely next move is to expand the tunnel or use it for C2 and exfiltration. Analyst pivot: **dns.question.name; source.ip dns.question.name** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

### [Long Connections](../queries/phase-08-command-and-control/03-long-connections.md)

#### Why Hunt This

Hunt for **Long Connections** because long sessions can expose reverse shells, tunnels, or persistent remote control. This query searches **event.dataset:zeek.conn** and organizes matches by **source.ip destination.ip destination.port; destination.as.organization.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can hold a session open for interactive control or protocol tunneling. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which destinations permit persistent sessions. From **Long Connections**, the likely next move is to relay traffic, administer the host, or stage transfer. Analyst pivot: **source.ip destination.ip destination.port; destination.as.organization.name** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

### [JA3](../queries/phase-08-command-and-control/04-ja3.md)

#### Why Hunt This

Hunt for **JA3** because TLS fingerprints can cluster the same client or server implementation across changing infrastructure. This query searches **event.dataset:zeek.ssl** and organizes matches by **tls.client.ja3; source.ip destination.ip tls.client.server_name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use a malware or offensive-framework TLS stack that differs from approved software. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts share the same TLS implementation. From **JA3**, the likely next move is to rotate infrastructure or change the TLS stack. Analyst pivot: **tls.client.ja3; source.ip destination.ip tls.client.server_name** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

### [Rare Domains](../queries/phase-08-command-and-control/05-rare-domains.md)

#### Why Hunt This

Hunt for **Rare Domains** because low-prevalence domains are more likely to represent new or campaign-specific infrastructure. This query searches **event.dataset:zeek.dns, event.dataset:zeek.ssl, event.dataset:zeek.http** and organizes matches by **dns.question.name; tls.client.server_name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use a new or compromised domain for delivery, redirects, phishing, or C2. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts resolve the domain and which addresses support it. From **Rare Domains**, the likely next move is to contact the infrastructure or rotate subdomains and addresses. Analyst pivot: **dns.question.name; tls.client.server_name** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

### [User Agents](../queries/phase-08-command-and-control/06-user-agents.md)

#### Why Hunt This

Hunt for **User Agents** because rare or malformed user agents can expose scripted clients and malware. This query searches **event.dataset:zeek.http** and organizes matches by **user_agent.original; source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can spoof or customize a user agent to blend C2 or downloads into web traffic. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which HTTP client identity passes controls. From **User Agents**, the likely next move is to imitate a browser or move to encrypted traffic. Analyst pivot: **user_agent.original; source.ip destination.ip** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

### [Http Post](../queries/phase-08-command-and-control/07-http-post.md)

#### Why Hunt This

Hunt for **Http Post** because repeated or high-volume POST requests can expose command results or outbound data. This query searches **event.dataset:zeek.http** and organizes matches by **source.ip url.domain; source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can send host data or stolen content in HTTP request bodies. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which URI and destination accept uploads. From **Http Post**, the likely next move is to increase transfer volume or switch to HTTPS. Analyst pivot: **source.ip url.domain; source.ip destination.ip** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

### [TLS](../queries/phase-08-command-and-control/08-tls.md)

#### Why Hunt This

Hunt for **TLS** because TLS metadata reveals SNI, certificates, versions, fingerprints, and encrypted session outcomes. This query searches **event.dataset:zeek.ssl, event.dataset:zeek.x509** and organizes matches by **source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can hide delivery or C2 content inside encryption while leaking handshake metadata. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which names, certificates, and clients identify the encrypted channel. From **TLS**, the likely next move is to cluster related hosts or pivot to the responsible endpoint process. Analyst pivot: **source.ip destination.ip** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

### [Proxy And Reverse Tunnel](../queries/phase-08-command-and-control/09-proxy-and-reverse-tunnel.md)

#### Why Hunt This

Hunt for **Proxy And Reverse Tunnel** because forwarding and proxy activity can reveal traffic relayed through a compromised host. This query searches **event.dataset:zeek.conn** and organizes matches by **destination.ip destination.port network.bytes event.duration**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can create SOCKS, SSH, or reverse tunnels into otherwise unreachable networks. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which host bridges zones and which port carries the tunnel. From **Proxy And Reverse Tunnel**, the likely next move is to scan protected segments or relay C2 and exfiltration. Analyst pivot: **destination.ip destination.port network.bytes event.duration** into **tool delivery, movement, collection, or exfiltration**, then verify the sequence with an independent telemetry source.

## Pivots and evidence preservation

Use Phases 2 and 13 to scope infrastructure, Phase 10 for execution, and Phase 9 for transfer.
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

What process communicates with which infrastructure, how regularly, and why is it normal or suspicious? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

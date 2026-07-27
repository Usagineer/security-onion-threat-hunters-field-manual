# Phase 4 - Discovery

 **Analyst question:** What did the process or actor learn, and which discovered targets should be scoped next?

## What this phase is for

Identify reconnaissance of accounts, hosts, networks, sessions, processes, and services.

## What makes a result meaningful

A single administration command can be normal; a clustered sequence, unusual parent, or post-compromise timing is stronger.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Whoami](../queries/security-onion/phase-04-discovery/01-whoami.md)

#### Why Hunt This

Hunt for **Whoami** because identity discovery reveals the current user, groups, privileges, and integrity level. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **host.name process.parent.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can check whether the foothold already has useful privileges. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned the effective identity and token capabilities. From **Whoami**, the likely next move is to choose escalation, credential theft, or permitted actions. Analyst pivot: **host.name process.parent.name** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Hostname Ipconfig](../queries/security-onion/phase-04-discovery/02-hostname-ipconfig.md)

#### Why Hunt This

Hunt for **Hostname Ipconfig** because host and IP configuration reveal system identity, interfaces, DNS, gateways, and subnets. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **host.name process.parent.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can orient a foothold within the network. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned the host name, address ranges, DNS suffix, and routes. From **Hostname Ipconfig**, the likely next move is to target local subnets or choose egress. Analyst pivot: **host.name process.parent.name** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Arp Route](../queries/security-onion/phase-04-discovery/03-arp-route.md)

#### Why Hunt This

Hunt for **Arp Route** because ARP and routing data reveal neighbors, gateways, and reachable paths without a broad scan. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can identify nearby systems and routes from local state. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned neighbor addresses, gateways, and additional subnets. From **Arp Route**, the likely next move is to probe selected hosts or cross a routed boundary. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Systeminfo](../queries/security-onion/phase-04-discovery/04-systeminfo.md)

#### Why Hunt This

Hunt for **Systeminfo** because system information reveals OS build, architecture, hotfixes, domain role, and uptime. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can profile a host for compatible exploits and payloads. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned the platform, missing patches, architecture, and role. From **Systeminfo**, the likely next move is to select an exploit or deploy the correct binary. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Net User Group](../queries/security-onion/phase-04-discovery/05-net-user-group.md)

#### Why Hunt This

Hunt for **Net User Group** because account and group enumeration reveals users and privileged memberships. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **host.name process.command_line**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can identify administrators, service accounts, and identities worth attacking. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which accounts exist and which groups confer privilege. From **Net User Group**, the likely next move is to spray, steal, or impersonate a selected identity. Analyst pivot: **host.name process.command_line** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Nltest](../queries/security-onion/phase-04-discovery/06-nltest.md)

#### Why Hunt This

Hunt for **Nltest** because nltest reveals domain controllers, trusts, and secure-channel relationships. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can map authentication infrastructure and trust paths. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which controllers and domains accept credentials. From **Nltest**, the likely next move is to attack directory services or cross a trust. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Netstat](../queries/security-onion/phase-04-discovery/07-netstat.md)

#### Why Hunt This

Hunt for **Netstat** because netstat exposes listeners, active connections, endpoints, and owning processes. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can identify services, security tools, and usable communication paths. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which ports listen and which remote systems are trusted. From **Netstat**, the likely next move is to connect locally or mimic an approved channel. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Tasklist](../queries/security-onion/phase-04-discovery/08-tasklist.md)

#### Why Hunt This

Hunt for **Tasklist** because process enumeration exposes applications, security products, and privileged processes. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can profile defenses and select credential or injection targets. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which controls and useful processes are running. From **Tasklist**, the likely next move is to evade defenses, dump credentials, or inject code. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Quser Query User](../queries/security-onion/phase-04-discovery/09-quser-query-user.md)

#### Why Hunt This

Hunt for **Quser Query User** because session enumeration identifies active and disconnected users. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can locate privileged sessions for hijacking or token theft. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which users and sessions are present. From **Quser Query User**, the likely next move is to target or impersonate a privileged session. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Powershell Discovery](../queries/security-onion/phase-04-discovery/10-powershell-discovery.md)

#### Why Hunt This

Hunt for **Powershell Discovery** because PowerShell can automate host, domain, process, and network discovery. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can collect broad environmental data through built-in capabilities. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned the same inventory available to an administrator. From **Powershell Discovery**, the likely next move is to feed discoveries into credential, movement, and collection scripts. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Network Service Enumeration](../queries/security-onion/phase-04-discovery/11-network-service-enumeration.md)

#### Why Hunt This

Hunt for **Network Service Enumeration** because service probing identifies reachable protocols and remote-access paths. This query searches **event.dataset:zeek.conn, event.dataset:zeek.notice, ports 135/139/445/389/636** and organizes matches by **destination.ip destination.port connection.state; destination.ip destination.port network.protocol**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can scan hosts for exploitable services or valid-account entry points. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which ports, systems, and protocols respond. From **Network Service Enumeration**, the likely next move is to exploit or authenticate to a discovered service. Analyst pivot: **destination.ip destination.port connection.state; destination.ip destination.port network.protocol** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

### [Icmp And Subnet Discovery](../queries/security-onion/phase-04-discovery/12-icmp-and-subnet-discovery.md)

#### Why Hunt This

Hunt for **Icmp And Subnet Discovery** because ICMP and subnet probing identify live hosts and reachable address space. This query searches **event.dataset:zeek.conn, event.dataset:zeek.notice** and organizes matches by **destination.ip; destination.ip destination.port**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can build a target list before detailed service enumeration. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which IPs respond and where network boundaries exist. From **Icmp And Subnet Discovery**, the likely next move is to scan responsive hosts and prioritize infrastructure. Analyst pivot: **destination.ip; destination.ip destination.port** into **credential access or lateral movement**, then verify the sequence with an independent telemetry source.

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

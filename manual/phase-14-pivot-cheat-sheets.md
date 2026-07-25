# Phase 14 - Pivot Cheat Sheets

 **Analyst question:** What exact value should be pivoted next, and which detailed phase owns the resulting behavior?

## What this phase is for

Choose a fast, evidence-preserving next search after a common finding.

## What makes a result meaningful

A cheat sheet accelerates triage but does not replace the full phase methodology or corroboration.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Found Beaconing](../queries/phase-14-pivot-cheat-sheets/found-beaconing.md)

#### Why Hunt This

Hunt for **Found Beaconing** because repeated low-variance connections can reveal an automated implant calling home. This query searches **event.dataset:zeek.conn, event.dataset:zeek.ssl, event.dataset:zeek.http, event.module:suricata, event.module:endpoint** and organizes matches by **tls.client.ja3 tls.client.server_name; url.original user_agent.original**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can poll C2 at fixed or jittered intervals while generating little traffic. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts are infected and how reliably C2 is reachable. From **Found Beaconing**, the likely next move is to deliver tasks, change timing, or move to backup C2. Analyst pivot: **tls.client.ja3 tls.client.server_name; url.original user_agent.original** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

### [Found Dns](../queries/phase-14-pivot-cheat-sheets/found-dns.md)

#### Why Hunt This

Hunt for **Found Dns** because DNS evidence links queried names, answers, clients, and subsequent connections. This query searches **event.dataset:zeek.dns, event.dataset:zeek.conn, event.dataset:zeek.ssl, event.module:suricata** and organizes matches by **source.ip dns.answers; source.ip destination.port**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can resolve delivery or C2 infrastructure, use dynamic answers, or bypass approved resolvers. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which host queried which name and which address it received. From **Found Dns**, the likely next move is to connect to the answer, rotate infrastructure, or tunnel through DNS. Analyst pivot: **source.ip dns.answers; source.ip destination.port** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

### [Found Powershell](../queries/phase-14-pivot-cheat-sheets/found-powershell.md)

#### Why Hunt This

Hunt for **Found Powershell** because PowerShell ancestry, arguments, and network activity can expose a complete execution chain. This query searches **event.module:endpoint** and organizes matches by **destination.ip destination.port; process.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use PowerShell for discovery, download, execution, credentials, and evasion. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which user, parent, script, and privilege are involved. From **Found Powershell**, the likely next move is to run another stage, persist, or execute remotely. Analyst pivot: **destination.ip destination.port; process.name** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

### [Found Rdp](../queries/phase-14-pivot-cheat-sheets/found-rdp.md)

#### Why Hunt This

Hunt for **Found Rdp** because RDP traffic and logons identify interactive Windows access, its account, source, target, and result. This query searches **event.dataset:zeek.conn, event.code:4624, event.code:4625, event.code:4778, ports 3389** and organizes matches by **source.ip winlog.event_data.TargetUserName host.name; source.ip winlog.event_data.TargetUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can authenticate with guessed, stolen, or reused credentials for an interactive desktop. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which Windows host and credential permit interactive access. From **Found Rdp**, the likely next move is to run discovery, steal credentials, or establish persistence. Analyst pivot: **source.ip winlog.event_data.TargetUserName host.name; source.ip winlog.event_data.TargetUserName** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

### [Found Repeated Powershell](../queries/phase-14-pivot-cheat-sheets/found-repeated-powershell.md)

#### Why Hunt This

Hunt for **Found Repeated Powershell** because repeated PowerShell can expose automation, persistence, remote management, or recurring execution. This query searches **event.code:4698** and organizes matches by **process.command_line host.name user.name; host.name user.name process.parent.name process.command_line**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can rerun scripts through tasks, services, WinRM, or C2. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which command and trigger recur. From **Found Repeated Powershell**, the likely next move is to refresh persistence or retrieve more commands. Analyst pivot: **process.command_line host.name user.name; host.name user.name process.parent.name process.command_line** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

### [Found Smb](../queries/phase-14-pivot-cheat-sheets/found-smb.md)

#### Why Hunt This

Hunt for **Found Smb** because SMB connections, shares, and file operations reveal Windows file access and admin-share use. This query searches **event.dataset:zeek.smb_mapping, event.dataset:zeek.smb_files, event.code:7045, event.code:4624** and organizes matches by **smb.share; file.name**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can enumerate shares, copy tools, collect data, or execute through administrative shares. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts expose shares and which accounts can write. From **Found Smb**, the likely next move is to stage a payload, create a service, or move laterally. Analyst pivot: **smb.share; file.name** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

### [Found Suspicious Ip](../queries/phase-14-pivot-cheat-sheets/found-suspicious-ip.md)

#### Why Hunt This

Hunt for **Found Suspicious Ip** because an IP sweep identifies every source/destination relationship tied to known infrastructure. This query searches **event.dataset:zeek.dns, event.dataset:zeek.http, event.dataset:zeek.ssl, event.dataset:zeek.smb_mapping, event.dataset:zeek.smb_files** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can reuse an address for delivery, C2, scanning, staging, or transfer. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts and processes contacted it. From **Found Suspicious Ip**, the likely next move is to rotate infrastructure or continue on compromised hosts. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

### [Found Telemetry Gap](../queries/phase-14-pivot-cheat-sheets/found-telemetry-gap.md)

#### Why Hunt This

Hunt for **Found Telemetry Gap** because a sudden telemetry gap can indicate failure, isolation, tampering, or defense impairment. This query searches **event.dataset:zeek.conn** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can disable or evade collection before louder actions. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which host is blind and whether network activity continues. From **Found Telemetry Gap**, the likely next move is to dump credentials, move, or exfiltrate unseen. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

### [Found Winrm](../queries/phase-14-pivot-cheat-sheets/found-winrm.md)

#### Why Hunt This

Hunt for **Found Winrm** because WinRM and wsmprovhost evidence identify remote PowerShell execution. This query searches **event.dataset:zeek.conn, event.code:4624, ports 5985/5986** and organizes matches by **source.ip winlog.event_data.TargetUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can run commands remotely through Windows management with valid credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts and accounts permit noninteractive administration. From **Found Winrm**, the likely next move is to deploy scripts, collect credentials, or continue movement. Analyst pivot: **source.ip winlog.event_data.TargetUserName** into **the full behavior phase named by the finding**, then verify the sequence with an independent telemetry source.

## Pivots and evidence preservation

Return to the linked behavior phase and document the pivot chain, conclusion, and outstanding questions.
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

What exact value should be pivoted next, and which detailed phase owns the resulting behavior? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

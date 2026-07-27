# Phase 5 - Credential Access

 **Analyst question:** What credential material was targeted, who performed the action, and where may it have been used?

## What this phase is for

Detect theft or abuse of passwords, hashes, tickets, registry hives, LSASS, and directory secrets.

## What makes a result meaningful

High-impact actions need endpoint, account, target, command-line, and authorization context before classification.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Lsass Access](../queries/security-onion/phase-05-credential-access/01-lsass-access.md)

#### Why Hunt This

Hunt for **Lsass Access** because LSASS access can indicate attempted theft of passwords, NTLM hashes, and Kerberos material. This query searches **event.code:10** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can read or dump authentication memory after obtaining sufficient privilege. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which reusable credentials are present. From **Lsass Access**, the likely next move is to pass hashes or tickets and move laterally. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

### [Mimikatz](../queries/security-onion/phase-05-credential-access/02-mimikatz.md)

#### Why Hunt This

Hunt for **Mimikatz** because Mimikatz behavior is a high-signal indicator of credential and ticket theft. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can extract secrets, manipulate Kerberos tickets, or impersonate identities. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which credentials and protections are present. From **Mimikatz**, the likely next move is to perform pass-the-hash, pass-the-ticket, or DCSync. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

### [Dcsync](../queries/security-onion/phase-05-credential-access/03-dcsync.md)

#### Why Hunt This

Hunt for **Dcsync** because replication requests from non-domain controllers can reveal theft of directory credential data. This query searches **event.dataset:zeek.dce_rpc, event.code:4662** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can impersonate a domain controller using replication rights. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned whether domain password material can be requested remotely. From **Dcsync**, the likely next move is to obtain privileged hashes and compromise more identities. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

### [Kerberoasting](../queries/security-onion/phase-05-credential-access/04-kerberoasting.md)

#### Why Hunt This

Hunt for **Kerberoasting** because unusual service-ticket requests can expose service accounts selected for offline cracking. This query searches **event.dataset:zeek.kerberos, event.code:4769** and organizes matches by **winlog.event_data.ServiceName winlog.event_data.TargetUserName**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can request SPN tickets and crack them without repeated authentication. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which service accounts use weak passwords or encryption. From **Kerberoasting**, the likely next move is to recover a service credential and access its resources. Analyst pivot: **winlog.event_data.ServiceName winlog.event_data.TargetUserName** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

### [Asrep Roasting](../queries/security-onion/phase-05-credential-access/05-asrep-roasting.md)

#### Why Hunt This

Hunt for **Asrep Roasting** because AS-REP responses identify preauthentication-disabled accounts exposed to offline cracking. This query searches **event.dataset:zeek.kerberos, event.code:4768** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can request crackable authentication material without knowing a password. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which accounts are misconfigured and crackable. From **Asrep Roasting**, the likely next move is to recover a password and use the account for access. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

### [Procdump](../queries/security-onion/phase-05-credential-access/06-procdump.md)

#### Why Hunt This

Hunt for **Procdump** because ProcDump against sensitive processes can expose credential-dump staging with a legitimate utility. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can write LSASS memory to disk for offline extraction. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned whether LSASS can be accessed and where dumps can be written. From **Procdump**, the likely next move is to extract, compress, and transfer credentials. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

### [Sam](../queries/security-onion/phase-05-credential-access/07-sam.md)

#### Why Hunt This

Hunt for **Sam** because SAM and SYSTEM hive activity can reveal theft of local password hashes. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can export hives and derive local hashes offline. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which local accounts and reusable passwords exist. From **Sam**, the likely next move is to crack or pass a local administrator hash. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

### [Ntds Dit](../queries/security-onion/phase-05-credential-access/08-ntds-dit.md)

#### Why Hunt This

Hunt for **Ntds Dit** because NTDS.dit access can indicate theft of the Active Directory credential database. This query searches **event.dataset:zeek.smb_files** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can copy NTDS.dit and SYSTEM data for offline domain-hash extraction. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned whether domain database files are accessible. From **Ntds Dit**, the likely next move is to forge authentication and compromise the domain at scale. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

### [Registry Hive And Sql Shell](../queries/security-onion/phase-05-credential-access/09-registry-hive-and-sql-shell.md)

#### Why Hunt This

Hunt for **Registry Hive And Sql Shell** because database connections and command-shell behavior can expose database and host compromise. This query searches **the query file's protocol, process, identity, or indicator filters** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can steal database credentials or enable command features such as xp_cmdshell. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which database accepts access and whether its service can run OS commands. From **Registry Hive And Sql Shell**, the likely next move is to dump data, execute payloads, or pivot from the database host. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **privilege escalation and lateral movement**, then verify the sequence with an independent telemetry source.

## Pivots and evidence preservation

Use Phases 6 and 11 to trace resulting logons and movement.
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

What credential material was targeted, who performed the action, and where may it have been used? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

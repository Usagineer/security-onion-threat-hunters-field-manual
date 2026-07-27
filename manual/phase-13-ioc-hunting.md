# Phase 13 - IOC Hunting

 **Analyst question:** Which assets match the indicator, is the match meaningful, and what related behavior must be investigated?

## What this phase is for

Scope known IPs, domains, URLs, hashes, fingerprints, user agents, YARA, and Sigma results.

## What makes a result meaningful

Indicator quality, specificity, recency, and shared infrastructure determine how much confidence a match deserves.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Ip](../queries/security-onion/phase-13-ioc-hunting/01-ip.md)

#### Why Hunt This

Hunt for **Ip** because an IP sweep identifies every source/destination relationship tied to known infrastructure. This query searches **event.dataset:zeek.dns** and organizes matches by **event.dataset**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can reuse an address for delivery, C2, scanning, staging, or transfer. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts and processes contacted it. From **Ip**, the likely next move is to rotate infrastructure or continue on compromised hosts. Analyst pivot: **event.dataset** into **affected hosts and the behavior represented by the IOC**, then verify the sequence with an independent telemetry source.

### [Domain](../queries/security-onion/phase-13-ioc-hunting/02-domain.md)

#### Why Hunt This

Hunt for **Domain** because a domain sweep correlates DNS, HTTP host, and TLS SNI evidence. This query searches **event.dataset:zeek.dns** and organizes matches by **source.ip; dns.answers**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use a name for phishing, delivery, redirects, dynamic resolution, or C2. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts resolve and contact the name. From **Domain**, the likely next move is to rotate addresses or retrieve payloads. Analyst pivot: **source.ip; dns.answers** into **affected hosts and the behavior represented by the IOC**, then verify the sequence with an independent telemetry source.

### [Url](../queries/security-onion/phase-13-ioc-hunting/03-url.md)

#### Why Hunt This

Hunt for **Url** because a URL identifies an exact lure, payload path, API route, or C2 endpoint. This query searches **event.dataset:zeek.http** and organizes matches by **source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can host malicious content or tasking at a specific path. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which user, process, request, and response are involved. From **Url**, the likely next move is to download content or switch paths. Analyst pivot: **source.ip destination.ip** into **affected hosts and the behavior represented by the IOC**, then verify the sequence with an independent telemetry source.

### [Hash](../queries/security-onion/phase-13-ioc-hunting/04-hash.md)

#### Why Hunt This

Hunt for **Hash** because a file hash identifies an exact known artifact. This query searches **event.dataset:zeek.files, event.dataset:strelka, event.module:endpoint** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can deploy the same payload, loader, archive, or tool to multiple hosts. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned where the artifact exists or ran. From **Hash**, the likely next move is to recompile it or continue on affected hosts. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **affected hosts and the behavior represented by the IOC**, then verify the sequence with an independent telemetry source.

### [JA3](../queries/security-onion/phase-13-ioc-hunting/05-ja3.md)

#### Why Hunt This

Hunt for **JA3** because TLS fingerprints can cluster the same client or server implementation across changing infrastructure. This query searches **event.dataset:zeek.ssl** and organizes matches by **source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can use a malware or offensive-framework TLS stack that differs from approved software. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which hosts share the same TLS implementation. From **JA3**, the likely next move is to rotate infrastructure or change the TLS stack. Analyst pivot: **source.ip destination.ip** into **affected hosts and the behavior represented by the IOC**, then verify the sequence with an independent telemetry source.

### [User Agent](../queries/security-onion/phase-13-ioc-hunting/06-user-agent.md)

#### Why Hunt This

Hunt for **User Agent** because rare or malformed user agents can expose scripted clients and malware. This query searches **event.dataset:zeek.http** and organizes matches by **source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can spoof or customize a user agent to blend C2 or downloads into web traffic. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which HTTP client identity passes controls. From **User Agent**, the likely next move is to imitate a browser or move to encrypted traffic. Analyst pivot: **source.ip destination.ip** into **affected hosts and the behavior represented by the IOC**, then verify the sequence with an independent telemetry source.

### [YARA](../queries/security-onion/phase-13-ioc-hunting/07-yara.md)

#### Why Hunt This

Hunt for **YARA** because YARA matches identify files or memory by structural features. This query searches **event.dataset:strelka** and organizes matches by **file.name source.ip destination.ip; strelka.scan.yara.matches**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can reuse code and configuration despite changing hashes. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which malware family or capability is present. From **YARA**, the likely next move is to deploy variants or keep the same behavior. Analyst pivot: **file.name source.ip destination.ip; strelka.scan.yara.matches** into **affected hosts and the behavior represented by the IOC**, then verify the sequence with an independent telemetry source.

### [Sigma](../queries/security-onion/phase-13-ioc-hunting/08-sigma.md)

#### Why Hunt This

Hunt for **Sigma** because Sigma matches identify normalized behavior across log sources. This query searches **event.module:soc** and organizes matches by **the matching host, account, process, source, destination, and timestamp**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can change tools while preserving the same technique. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which behavior and log source reveal the operation. From **Sigma**, the likely next move is to switch binaries or syntax while continuing. Analyst pivot: **the matching host, account, process, source, destination, and timestamp** into **affected hosts and the behavior represented by the IOC**, then verify the sequence with an independent telemetry source.

## Pivots and evidence preservation

Use Phase 2 for affected hosts and IPs, Phase 8 for infrastructure, and Phase 10 for execution.
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

Which assets match the indicator, is the match meaningful, and what related behavior must be investigated? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

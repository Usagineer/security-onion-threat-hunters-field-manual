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

#### What this query is for

Use the **Beaconing** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Beaconing** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Dns Tunneling](../queries/phase-08-command-and-control/02-dns-tunneling.md)

#### What this query is for

Use the **Dns Tunneling** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Dns Tunneling** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Long Connections](../queries/phase-08-command-and-control/03-long-connections.md)

#### What this query is for

Use the **Long Connections** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Long Connections** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [JA3](../queries/phase-08-command-and-control/04-ja3.md)

#### What this query is for

Use the **JA3** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **JA3** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Rare Domains](../queries/phase-08-command-and-control/05-rare-domains.md)

#### What this query is for

Use the **Rare Domains** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Rare Domains** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [User Agents](../queries/phase-08-command-and-control/06-user-agents.md)

#### What this query is for

Use the **User Agents** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **User Agents** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Http Post](../queries/phase-08-command-and-control/07-http-post.md)

#### What this query is for

Use the **Http Post** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Http Post** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [TLS](../queries/phase-08-command-and-control/08-tls.md)

#### What this query is for

Use the **TLS** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **TLS** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Proxy And Reverse Tunnel](../queries/phase-08-command-and-control/09-proxy-and-reverse-tunnel.md)

#### What this query is for

Use the **Proxy And Reverse Tunnel** query to identify command channels, tunnels, and suspicious infrastructure. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Proxy And Reverse Tunnel** to maintain remote control, deliver tools, hide traffic in expected protocols, or tunnel to other systems. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

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

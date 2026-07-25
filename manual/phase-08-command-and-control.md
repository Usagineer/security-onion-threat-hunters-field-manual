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

**Why use it:** Looks for command-and-control behavior involving Beaconing. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Dns Tunneling](../queries/phase-08-command-and-control/02-dns-tunneling.md)

**Why use it:** Looks for command-and-control behavior involving Dns Tunneling. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Long Connections](../queries/phase-08-command-and-control/03-long-connections.md)

**Why use it:** Looks for command-and-control behavior involving Long Connections. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [JA3](../queries/phase-08-command-and-control/04-ja3.md)

**Why use it:** Looks for command-and-control behavior involving Ja3. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Rare Domains](../queries/phase-08-command-and-control/05-rare-domains.md)

**Why use it:** Looks for command-and-control behavior involving Rare Domains. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [User Agents](../queries/phase-08-command-and-control/06-user-agents.md)

**Why use it:** Looks for command-and-control behavior involving User Agents. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Http Post](../queries/phase-08-command-and-control/07-http-post.md)

**Why use it:** Looks for command-and-control behavior involving Http Post. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [TLS](../queries/phase-08-command-and-control/08-tls.md)

**Why use it:** Looks for command-and-control behavior involving Tls. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Proxy And Reverse Tunnel](../queries/phase-08-command-and-control/09-proxy-and-reverse-tunnel.md)

**Why use it:** Looks for command-and-control behavior involving Proxy And Reverse Tunnel. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use this channel to receive commands, deliver tools, tunnel traffic, or maintain an interactive session while hiding in expected protocols. Pivot to the responsible process, shared infrastructure, other affected hosts, and any transfer or staging behavior.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

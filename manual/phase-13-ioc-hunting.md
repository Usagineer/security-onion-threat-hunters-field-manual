# Phase 13 - IOC Hunting

 **Analyst question:** Which assets match the indicator, is the match meaningful, and what related behavior must be investigated?

## What this phase is for

Scope known IPs, domains, URLs, hashes, fingerprints, user agents, YARA, and Sigma results.

## What makes a result meaningful

Indicator quality, specificity, recency, and shared infrastructure determine how much confidence a match deserves.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Ip](../queries/phase-13-ioc-hunting/01-ip.md)

**Why use it:** Searches Security Onion telemetry for the specified indicator type: Ip. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Domain](../queries/phase-13-ioc-hunting/02-domain.md)

**Why use it:** Searches Security Onion telemetry for the specified indicator type: Domain. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Url](../queries/phase-13-ioc-hunting/03-url.md)

**Why use it:** Searches Security Onion telemetry for the specified indicator type: Url. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Hash](../queries/phase-13-ioc-hunting/04-hash.md)

**Why use it:** Searches Security Onion telemetry for the specified indicator type: Hash. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [JA3](../queries/phase-13-ioc-hunting/05-ja3.md)

**Why use it:** Searches Security Onion telemetry for the specified indicator type: Ja3. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [User Agent](../queries/phase-13-ioc-hunting/06-user-agent.md)

**Why use it:** Searches Security Onion telemetry for the specified indicator type: User Agent. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [YARA](../queries/phase-13-ioc-hunting/07-yara.md)

**Why use it:** Searches Security Onion telemetry for the specified indicator type: Yara. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Sigma](../queries/phase-13-ioc-hunting/08-sigma.md)

**Why use it:** Searches Security Onion telemetry for the specified indicator type: Sigma. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

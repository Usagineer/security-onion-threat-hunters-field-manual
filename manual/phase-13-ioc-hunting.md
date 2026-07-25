# Phase 13 - IOC Hunting

 **Analyst question:** Which assets match the indicator, is the match meaningful, and what related behavior must be investigated?

## What this phase is for

Scope known IPs, domains, URLs, hashes, fingerprints, user agents, YARA, and Sigma results.

## Before you run a query

1. Set an absolute time range and note its timezone.
2. Write down the starting lead and the asset, account, or service ownership.
3. Replace all placeholders with case values; do not broaden searches until the first result is understood.
4. Save the result count and the values that become your next pivot.

## Investigation method

1. **Start narrow.** Use the file that matches the observed behavior, host, account, protocol, or indicator.
2. **Characterize the result.** Identify source, target, user, process, command line, time, and outcome.
3. **Corroborate.** Check an independent source such as endpoint, network, identity, DNS, TLS, or Suricata evidence.
4. **Compare with normal.** Validate role, approved tooling, maintenance windows, historical behavior, and clean peers.
5. **Scope and decide.** Search the same artifact or behavior across the estate, preserve evidence, and document a benign explanation or escalation rationale.

## What makes a result meaningful

Indicator quality, specificity, recency, and shared infrastructure determine how much confidence a match deserves.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [01-ip](../queries/phase-13-ioc-hunting/01-ip.md)
- [02-domain](../queries/phase-13-ioc-hunting/02-domain.md)
- [03-url](../queries/phase-13-ioc-hunting/03-url.md)
- [04-hash](../queries/phase-13-ioc-hunting/04-hash.md)
- [05-ja3](../queries/phase-13-ioc-hunting/05-ja3.md)
- [06-user-agent](../queries/phase-13-ioc-hunting/06-user-agent.md)
- [07-yara](../queries/phase-13-ioc-hunting/07-yara.md)
- [08-sigma](../queries/phase-13-ioc-hunting/08-sigma.md)

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

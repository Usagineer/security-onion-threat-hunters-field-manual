# Phase 8 - Command and Control

 **Analyst question:** What process communicates with which infrastructure, how regularly, and why is it normal or suspicious?

## What this phase is for

Assess beaconing, DNS tunneling, TLS, HTTP, proxies, and tunnels used for operator communication.

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

Regular timing alone is not C2; stack timing, infrastructure rarity, process ancestry, and protocol details.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [01-beaconing](../queries/phase-08-command-and-control/01-beaconing.md)
- [02-dns-tunneling](../queries/phase-08-command-and-control/02-dns-tunneling.md)
- [03-long-connections](../queries/phase-08-command-and-control/03-long-connections.md)
- [04-ja3](../queries/phase-08-command-and-control/04-ja3.md)
- [05-rare-domains](../queries/phase-08-command-and-control/05-rare-domains.md)
- [06-user-agents](../queries/phase-08-command-and-control/06-user-agents.md)
- [07-http-post](../queries/phase-08-command-and-control/07-http-post.md)
- [08-tls](../queries/phase-08-command-and-control/08-tls.md)
- [09-proxy-and-reverse-tunnel](../queries/phase-08-command-and-control/09-proxy-and-reverse-tunnel.md)

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

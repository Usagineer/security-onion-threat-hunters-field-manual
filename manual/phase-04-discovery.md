# Phase 4 - Discovery

 **Analyst question:** What did the process or actor learn, and which discovered targets should be scoped next?

## What this phase is for

Identify reconnaissance of accounts, hosts, networks, sessions, processes, and services.

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

A single administration command can be normal; a clustered sequence, unusual parent, or post-compromise timing is stronger.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [01-whoami](../queries/phase-04-discovery/01-whoami.md)
- [02-hostname-ipconfig](../queries/phase-04-discovery/02-hostname-ipconfig.md)
- [03-arp-route](../queries/phase-04-discovery/03-arp-route.md)
- [04-systeminfo](../queries/phase-04-discovery/04-systeminfo.md)
- [05-net-user-group](../queries/phase-04-discovery/05-net-user-group.md)
- [06-nltest](../queries/phase-04-discovery/06-nltest.md)
- [07-netstat](../queries/phase-04-discovery/07-netstat.md)
- [08-tasklist](../queries/phase-04-discovery/08-tasklist.md)
- [09-quser-query-user](../queries/phase-04-discovery/09-quser-query-user.md)
- [10-powershell-discovery](../queries/phase-04-discovery/10-powershell-discovery.md)
- [11-network-service-enumeration](../queries/phase-04-discovery/11-network-service-enumeration.md)
- [12-icmp-and-subnet-discovery](../queries/phase-04-discovery/12-icmp-and-subnet-discovery.md)

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

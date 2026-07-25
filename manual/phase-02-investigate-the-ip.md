# Phase 2 - Investigate the Suspicious IP

 **Analyst question:** Which internal systems communicated with this IP, what did they do, and does the evidence support an incident?

## What this phase is for

Build a complete, IP-centered evidence picture from a network alert, IOC, or analyst lead.

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

A rare address alone is weak. Confidence rises when DNS, protocol logs, alerts, and endpoint telemetry describe the same activity.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [00-everything](../queries/phase-02-investigate-the-ip/00-everything.md)
- [01-smb](../queries/phase-02-investigate-the-ip/01-smb.md)
- [02-rdp](../queries/phase-02-investigate-the-ip/02-rdp.md)
- [03-winrm](../queries/phase-02-investigate-the-ip/03-winrm.md)
- [04-dns](../queries/phase-02-investigate-the-ip/04-dns.md)
- [05-http](../queries/phase-02-investigate-the-ip/05-http.md)
- [06-tls](../queries/phase-02-investigate-the-ip/06-tls.md)
- [07-suricata](../queries/phase-02-investigate-the-ip/07-suricata.md)
- [08-endpoint](../queries/phase-02-investigate-the-ip/08-endpoint.md)

## Pivots and evidence preservation

Pivot to Phases 3, 6, 8, 9, and 10 according to the observed behavior.
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

Which internal systems communicated with this IP, what did they do, and does the evidence support an incident? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

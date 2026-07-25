# Phase 12 - ICS / OT

 **Analyst question:** What operational function occurred, is it authorized, and what is the potential safety or production impact?

## What this phase is for

Safely investigate industrial protocol traffic, engineering activity, controllers, and IT-to-OT paths.

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

OT context and owner validation are mandatory; avoid active probing or disruptive containment without authority.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [01-modbus](../queries/phase-12-ics-ot/01-modbus.md)
- [02-ethernet-ip](../queries/phase-12-ics-ot/02-ethernet-ip.md)
- [03-cip](../queries/phase-12-ics-ot/03-cip.md)
- [04-dnp3](../queries/phase-12-ics-ot/04-dnp3.md)
- [05-bacnet](../queries/phase-12-ics-ot/05-bacnet.md)
- [06-opc-ua](../queries/phase-12-ics-ot/06-opc-ua.md)
- [07-s7](../queries/phase-12-ics-ot/07-s7.md)
- [08-engineering-workstations](../queries/phase-12-ics-ot/08-engineering-workstations.md)
- [09-plc-programming](../queries/phase-12-ics-ot/09-plc-programming.md)
- [10-unauthorized-controllers](../queries/phase-12-ics-ot/10-unauthorized-controllers.md)
- [11-it-ot-boundary-and-hmi-impact](../queries/phase-12-ics-ot/11-it-ot-boundary-and-hmi-impact.md)

## Pivots and evidence preservation

Coordinate with OT owners, then use Phases 6, 8, and 10 only when safe and relevant.
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

What operational function occurred, is it authorized, and what is the potential safety or production impact? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

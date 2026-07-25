# Phase 12 - ICS / OT

 **Analyst question:** What operational function occurred, is it authorized, and what is the potential safety or production impact?

## What this phase is for

Safely investigate industrial protocol traffic, engineering activity, controllers, and IT-to-OT paths.

## What makes a result meaningful

OT context and owner validation are mandatory; avoid active probing or disruptive containment without authority.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Modbus](../queries/phase-12-ics-ot/01-modbus.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Modbus. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Ethernet Ip](../queries/phase-12-ics-ot/02-ethernet-ip.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Ethernet Ip. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Cip](../queries/phase-12-ics-ot/03-cip.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Cip. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Dnp3](../queries/phase-12-ics-ot/04-dnp3.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Dnp3. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Bacnet](../queries/phase-12-ics-ot/05-bacnet.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Bacnet. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Opc Ua](../queries/phase-12-ics-ot/06-opc-ua.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Opc Ua. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [S7](../queries/phase-12-ics-ot/07-s7.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving S7. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Engineering Workstations](../queries/phase-12-ics-ot/08-engineering-workstations.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Engineering Workstations. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Plc Programming](../queries/phase-12-ics-ot/09-plc-programming.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Plc Programming. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Unauthorized Controllers](../queries/phase-12-ics-ot/10-unauthorized-controllers.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving Unauthorized Controllers. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [It Ot Boundary And Hmi Impact](../queries/phase-12-ics-ot/11-it-ot-boundary-and-hmi-impact.md)

**Why use it:** Reviews ICS/OT communications and impact-related activity involving It Ot Boundary And Hmi Impact. Use the results with the surrounding host, user, time, and network context before escalating.
Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

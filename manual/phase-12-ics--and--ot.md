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

#### What this query is for

Use the **Modbus** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Modbus** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Ethernet Ip](../queries/phase-12-ics-ot/02-ethernet-ip.md)

#### What this query is for

Use the **Ethernet Ip** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Ethernet Ip** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Cip](../queries/phase-12-ics-ot/03-cip.md)

#### What this query is for

Use the **Cip** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Cip** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Dnp3](../queries/phase-12-ics-ot/04-dnp3.md)

#### What this query is for

Use the **Dnp3** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Dnp3** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Bacnet](../queries/phase-12-ics-ot/05-bacnet.md)

#### What this query is for

Use the **Bacnet** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Bacnet** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Opc Ua](../queries/phase-12-ics-ot/06-opc-ua.md)

#### What this query is for

Use the **Opc Ua** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Opc Ua** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [S7](../queries/phase-12-ics-ot/07-s7.md)

#### What this query is for

Use the **S7** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **S7** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Engineering Workstations](../queries/phase-12-ics-ot/08-engineering-workstations.md)

#### What this query is for

Use the **Engineering Workstations** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Engineering Workstations** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Plc Programming](../queries/phase-12-ics-ot/09-plc-programming.md)

#### What this query is for

Use the **Plc Programming** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Plc Programming** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Unauthorized Controllers](../queries/phase-12-ics-ot/10-unauthorized-controllers.md)

#### What this query is for

Use the **Unauthorized Controllers** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Unauthorized Controllers** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [It Ot Boundary And Hmi Impact](../queries/phase-12-ics-ot/11-it-ot-boundary-and-hmi-impact.md)

#### What this query is for

Use the **It Ot Boundary And Hmi Impact** query to evaluate OT protocol and engineering activity with operational safety context. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **It Ot Boundary And Hmi Impact** to use engineering or control-system access to alter operations, gain control visibility, or affect availability and integrity. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

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

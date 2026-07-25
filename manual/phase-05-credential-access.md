# Phase 5 - Credential Access

 **Analyst question:** What credential material was targeted, who performed the action, and where may it have been used?

## What this phase is for

Detect theft or abuse of passwords, hashes, tickets, registry hives, LSASS, and directory secrets.

## What makes a result meaningful

High-impact actions need endpoint, account, target, command-line, and authorization context before classification.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Lsass Access](../queries/phase-05-credential-access/01-lsass-access.md)

#### What this query is for

Use the **Lsass Access** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Lsass Access** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Mimikatz](../queries/phase-05-credential-access/02-mimikatz.md)

#### What this query is for

Use the **Mimikatz** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Mimikatz** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Dcsync](../queries/phase-05-credential-access/03-dcsync.md)

#### What this query is for

Use the **Dcsync** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Dcsync** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Kerberoasting](../queries/phase-05-credential-access/04-kerberoasting.md)

#### What this query is for

Use the **Kerberoasting** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Kerberoasting** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Asrep Roasting](../queries/phase-05-credential-access/05-asrep-roasting.md)

#### What this query is for

Use the **Asrep Roasting** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Asrep Roasting** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Procdump](../queries/phase-05-credential-access/06-procdump.md)

#### What this query is for

Use the **Procdump** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Procdump** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Sam](../queries/phase-05-credential-access/07-sam.md)

#### What this query is for

Use the **Sam** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Sam** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Ntds Dit](../queries/phase-05-credential-access/08-ntds-dit.md)

#### What this query is for

Use the **Ntds Dit** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Ntds Dit** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

### [Registry Hive And Sql Shell](../queries/phase-05-credential-access/09-registry-hive-and-sql-shell.md)

#### What this query is for

Use the **Registry Hive And Sql Shell** query to find attempts to obtain passwords, hashes, tickets, or directory secrets. It narrows the investigation to the relevant records and exposes the host, account, source, destination, process, or timestamp that should become the next pivot.

#### Attacker use and next pivot

An attacker may abuse **Registry Hive And Sql Shell** to obtain reusable authentication material and impersonate an identity that can reach systems previously unavailable. A match can reveal the attacker's current position, intended objective, or the path to the next system or stage of the operation.

After a match, pivot on the most specific value in the result and look for related activity before and after the event. Confirm the behavior with another telemetry source and compare it with expected operations.

## Pivots and evidence preservation

Use Phases 6 and 11 to trace resulting logons and movement.
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

What credential material was targeted, who performed the action, and where may it have been used? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

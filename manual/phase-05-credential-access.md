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

**Why use it:** Looks for credential-access behavior involving Lsass Access. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Mimikatz](../queries/phase-05-credential-access/02-mimikatz.md)

**Why use it:** Looks for credential-access behavior involving Mimikatz. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Dcsync](../queries/phase-05-credential-access/03-dcsync.md)

**Why use it:** Looks for credential-access behavior involving Dcsync. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Kerberoasting](../queries/phase-05-credential-access/04-kerberoasting.md)

**Why use it:** Looks for credential-access behavior involving Kerberoasting. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Asrep Roasting](../queries/phase-05-credential-access/05-asrep-roasting.md)

**Why use it:** Looks for credential-access behavior involving Asrep Roasting. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Procdump](../queries/phase-05-credential-access/06-procdump.md)

**Why use it:** Looks for credential-access behavior involving Procdump. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Sam](../queries/phase-05-credential-access/07-sam.md)

**Why use it:** Looks for credential-access behavior involving Sam. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Ntds Dit](../queries/phase-05-credential-access/08-ntds-dit.md)

**Why use it:** Looks for credential-access behavior involving Ntds Dit. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

### [Registry Hive And Sql Shell](../queries/phase-05-credential-access/09-registry-hive-and-sql-shell.md)

**Why use it:** Looks for credential-access behavior involving Registry Hive And Sql Shell. Use the results with the surrounding host, user, time, and network context before escalating.
**Attacker use and next pivot:** An attacker may use obtained credentials, hashes, tickets, or secrets to impersonate users and reach systems that were previously unavailable. Follow with authentication analysis, remote-service activity, and use of the affected account on new hosts.

Use the matching records to identify the involved source, destination, account, process, and time. Then pivot on the most specific value and validate the behavior against normal operations.

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

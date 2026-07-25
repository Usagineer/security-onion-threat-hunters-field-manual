# Phase 3 - Initial Access

 **Analyst question:** What is the earliest defensible entry event, and what evidence connects it to execution on the affected system?

## What this phase is for

Determine how an actor first entered through remote access, public services, email, or user delivery.

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

Build a delivery or login chain rather than trusting a successful authentication event by itself.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [01-rdp](../queries/phase-03-initial-access/01-rdp.md)
- [02-vpn](../queries/phase-03-initial-access/02-vpn.md)
- [03-ssh](../queries/phase-03-initial-access/03-ssh.md)
- [04-web-attacks](../queries/phase-03-initial-access/04-web-attacks.md)
- [05-smb](../queries/phase-03-initial-access/05-smb.md)
- [06-mssql](../queries/phase-03-initial-access/06-mssql.md)
- [07-ftp](../queries/phase-03-initial-access/07-ftp.md)
- [08-email](../queries/phase-03-initial-access/08-email.md)
- [09-phishing](../queries/phase-03-initial-access/09-phishing.md)
- [10-drive-by-downloads](../queries/phase-03-initial-access/10-drive-by-downloads.md)
- [11-web-shell-and-server-side-rce](../queries/phase-03-initial-access/11-web-shell-and-server-side-rce.md)

## Pivots and evidence preservation

Use Phases 4, 6, 10, and 11 to scope activity that follows entry.
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

What is the earliest defensible entry event, and what evidence connects it to execution on the affected system? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

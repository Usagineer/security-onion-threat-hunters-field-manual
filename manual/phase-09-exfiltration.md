# Phase 9 - Exfiltration

 **Analyst question:** Was sensitive data collected, staged, or transmitted; by whom, to where, and with what evidence?

## What this phase is for

Investigate collection, staging, compression, and outbound transfer through protocols and cloud services.

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

Large transfers may be backup or synchronization; correlate with archive creation, exports, identity, and destination ownership.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [01-ftp](../queries/phase-09-exfiltration/01-ftp.md)
- [02-sftp](../queries/phase-09-exfiltration/02-sftp.md)
- [03-scp](../queries/phase-09-exfiltration/03-scp.md)
- [04-cloud-storage](../queries/phase-09-exfiltration/04-cloud-storage.md)
- [05-onedrive](../queries/phase-09-exfiltration/05-onedrive.md)
- [06-dropbox](../queries/phase-09-exfiltration/06-dropbox.md)
- [07-mega](../queries/phase-09-exfiltration/07-mega.md)
- [08-google-drive](../queries/phase-09-exfiltration/08-google-drive.md)
- [09-large-uploads](../queries/phase-09-exfiltration/09-large-uploads.md)
- [10-archive-creation](../queries/phase-09-exfiltration/10-archive-creation.md)
- [11-database-collection](../queries/phase-09-exfiltration/11-database-collection.md)

## Pivots and evidence preservation

Use Phase 8 for the channel and Phase 10 for the collection or transfer process.
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

Was sensitive data collected, staged, or transmitted; by whom, to where, and with what evidence? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

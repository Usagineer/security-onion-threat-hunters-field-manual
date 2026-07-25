# Phase 14 - Pivot Cheat Sheets

 **Analyst question:** What exact value should be pivoted next, and which detailed phase owns the resulting behavior?

## What this phase is for

Choose a fast, evidence-preserving next search after a common finding.

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

A cheat sheet accelerates triage but does not replace the full phase methodology or corroboration.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [found-beaconing](../queries/phase-14-pivot-cheat-sheets/found-beaconing.md)
- [found-dns](../queries/phase-14-pivot-cheat-sheets/found-dns.md)
- [found-powershell](../queries/phase-14-pivot-cheat-sheets/found-powershell.md)
- [found-rdp](../queries/phase-14-pivot-cheat-sheets/found-rdp.md)
- [found-repeated-powershell](../queries/phase-14-pivot-cheat-sheets/found-repeated-powershell.md)
- [found-smb](../queries/phase-14-pivot-cheat-sheets/found-smb.md)
- [found-suspicious-ip](../queries/phase-14-pivot-cheat-sheets/found-suspicious-ip.md)
- [found-telemetry-gap](../queries/phase-14-pivot-cheat-sheets/found-telemetry-gap.md)
- [found-winrm](../queries/phase-14-pivot-cheat-sheets/found-winrm.md)

## Pivots and evidence preservation

Return to the linked behavior phase and document the pivot chain, conclusion, and outstanding questions.
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

What exact value should be pivoted next, and which detailed phase owns the resulting behavior? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

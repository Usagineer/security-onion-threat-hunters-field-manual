# Phase 11 - Active Directory and Windows Events

 **Analyst question:** Which identities, systems, and event sequence prove or rule out suspicious access and directory change?

## What this phase is for

Reconstruct authentication, privilege, account, process, Kerberos, task, and service activity.

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

An event ID needs source, logon type, account role, target, and adjacent behavior to be useful.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Query inventory

The query files below are the operational starting points for this phase:

- [4624-successful-logon](../queries/phase-11-active-directory/4624-successful-logon.md)
- [4625-failed-logon](../queries/phase-11-active-directory/4625-failed-logon.md)
- [4672-special-privileges](../queries/phase-11-active-directory/4672-special-privileges.md)
- [4688-process-creation](../queries/phase-11-active-directory/4688-process-creation.md)
- [4698-scheduled-task-created](../queries/phase-11-active-directory/4698-scheduled-task-created.md)
- [4720-user-account-created](../queries/phase-11-active-directory/4720-user-account-created.md)
- [4728-member-added-global-group](../queries/phase-11-active-directory/4728-member-added-global-group.md)
- [4732-member-added-local-group](../queries/phase-11-active-directory/4732-member-added-local-group.md)
- [4768-kerberos-tgt-requested](../queries/phase-11-active-directory/4768-kerberos-tgt-requested.md)
- [4769-kerberos-service-ticket](../queries/phase-11-active-directory/4769-kerberos-service-ticket.md)
- [4771-kerberos-preauth-failed](../queries/phase-11-active-directory/4771-kerberos-preauth-failed.md)
- [7045-service-installed](../queries/phase-11-active-directory/7045-service-installed.md)

## Pivots and evidence preservation

Use Phases 5, 6, and 10 to corroborate identity events with credential, network, and execution evidence.
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

Which identities, systems, and event sequence prove or rule out suspicious access and directory change? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

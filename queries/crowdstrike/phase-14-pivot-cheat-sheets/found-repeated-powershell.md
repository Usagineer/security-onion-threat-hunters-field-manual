# Found repeated PowerShell -> scope propagation - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **found repeated powershell** to continue from a confirmed lead into its surrounding activity. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon process telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe$/i
| groupBy([aid, UserSid, ParentBaseFileName, CommandLine, SHA256HashData], function=[count(as=executions), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)], limit=max)
| executions>=3
| sort(executions, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

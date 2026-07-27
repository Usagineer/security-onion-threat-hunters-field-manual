# Event 4688 — Process Creation - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **process creation** to investigate Windows and Active Directory security events. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon endpoint telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| table([@timestamp, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, SHA256HashData], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

# Credential Access — DCSync - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **dcsync** to identify attempts to obtain reusable credentials or directory secrets. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon `DCSyncAttempted` telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=DCSyncAttempted
| groupBy([aid, UserName, RemoteAddressIP4], function=[count(as=attempts), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)], limit=max)
| sort(attempts, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

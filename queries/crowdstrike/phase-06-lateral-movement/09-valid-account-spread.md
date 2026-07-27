# Lateral Movement — Valid-Account Spread - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **valid account spread** to identify movement from one system or account to another. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon `UserLogon` telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=UserLogon
| bucket(span=30m)
| groupBy([UserName, _bucket], function=[count(aid, distinct=true, as=endpoints), count(RemoteAddressIP4, distinct=true, as=sources), collect([aid, RemoteAddressIP4, LogonType], limit=100)], limit=max)
| endpoints>=5
| sort(endpoints, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

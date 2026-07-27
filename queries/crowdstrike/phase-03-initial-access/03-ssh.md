# SSH — Initial Access - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **ssh** to identify how an attacker may have entered the environment. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon Linux logon telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(UserLogon|UserLogonFailed2)$/ event_platform=Lin
| RemoteAddressIP4=*
| groupBy([RemoteAddressIP4, UserName, aid, #event_simpleName], function=count(as=events), limit=max)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

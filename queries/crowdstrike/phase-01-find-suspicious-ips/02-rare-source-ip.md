# Rare Source IP - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **rare source ip** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon inbound network and logon telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(NetworkReceiveAcceptIP4|UserLogon|UserLogonFailed2)$/
| RemoteAddressIP4=*
| groupBy(RemoteAddressIP4, function=[count(as=events), count(aid, distinct=true, as=endpoints), collect([aid, LocalPort, UserName], limit=50)], limit=max)
| endpoints<=3
| sort(events, order=ascending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

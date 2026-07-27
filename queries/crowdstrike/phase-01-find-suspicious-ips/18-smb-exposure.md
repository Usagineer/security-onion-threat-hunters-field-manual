# SMB Exposure & Rare SMB - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **smb exposure** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon network telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4)$/
| RemotePort=/^445$/
| table([@timestamp, aid, ContextProcessId, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, Protocol], limit=2000)
```

```cql
#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4)$/
| RemotePort=/^445$/
| groupBy([RemoteAddressIP4, RemotePort], function=[count(as=connections), count(aid, distinct=true, as=endpoints)], limit=max)
| sort(connections, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

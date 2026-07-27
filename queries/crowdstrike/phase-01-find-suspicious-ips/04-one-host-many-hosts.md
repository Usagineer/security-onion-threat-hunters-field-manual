# One Host -> Many Hosts (Internal Fan-Out) - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **one host many hosts** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon `NetworkConnectIP4` telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=NetworkConnectIP4
| groupBy(aid, function=[count(RemoteAddressIP4, distinct=true, as=remoteHosts), count(as=connections), collect([RemoteAddressIP4, RemotePort], limit=100)], limit=max)
| remoteHosts>=25
| sort(remoteHosts, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

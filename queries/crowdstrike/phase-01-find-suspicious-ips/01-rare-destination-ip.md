# Rare Destination IP - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **rare destination ip** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon `NetworkConnectIP4` telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| groupBy(RemoteAddressIP4, function=[count(as=connections), count(aid, distinct=true, as=endpoints), collect([aid, RemotePort], limit=50)], limit=max)
| endpoints<=3
| sort(connections, order=ascending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

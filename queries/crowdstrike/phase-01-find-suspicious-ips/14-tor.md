# TOR - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **tor** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Normalized network and process telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
(destination.port=/^(9001|9030|9040|9050|9051|9150)$/ OR process.name=/^(tor|obfs4proxy)\.exe$/i)
| table([@timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, network.protocol, network.bytes, event.action, host.name, user.name], limit=2000)
```

```cql
(destination.port=/^(9001|9030|9040|9050|9051|9150)$/ OR process.name=/^(tor|obfs4proxy)\.exe$/i)
| groupBy([source.ip, destination.ip, destination.port], function=[count(as=events), sum(network.bytes, as=bytes)], limit=max)
| sort(events, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

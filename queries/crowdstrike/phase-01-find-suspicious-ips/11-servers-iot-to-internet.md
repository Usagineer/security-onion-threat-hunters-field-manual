# Servers / IoT Talking Directly to the Internet - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **servers iot to internet** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Normalized network telemetry with asset-role enrichment. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
(host.type=/^(server|iot|embedded)$/i OR observer.type=/^(server|iot)$/i) | !cidr(destination.ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| table([@timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, network.protocol, network.bytes, event.action, host.name, user.name], limit=2000)
```

```cql
(host.type=/^(server|iot|embedded)$/i OR observer.type=/^(server|iot)$/i) | !cidr(destination.ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| groupBy([source.ip, destination.ip, destination.port], function=[count(as=events), sum(network.bytes, as=bytes)], limit=max)
| sort(events, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

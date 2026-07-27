# ICS/OT — Engineering Workstations - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **engineering workstations** to identify unsafe or unauthorized industrial-control activity. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Industrial network telemetry normalized to CPS/ECS; parser-specific OT fields may require adjustment. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
(host.type=/engineering/i OR source.asset.type=/engineering/i) | destination.port=/^(102|502|4840|20000|44818|47808)$/
| table([@timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, network.protocol, network.bytes, event.action, host.name, user.name], limit=2000)
```

```cql
(host.type=/engineering/i OR source.asset.type=/engineering/i) | destination.port=/^(102|502|4840|20000|44818|47808)$/
| groupBy([source.ip, destination.ip, source.asset.name], function=[count(as=events), sum(network.bytes, as=bytes)], limit=max)
| sort(events, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.
- Join controller and engineering-workstation results to the authoritative OT asset inventory.

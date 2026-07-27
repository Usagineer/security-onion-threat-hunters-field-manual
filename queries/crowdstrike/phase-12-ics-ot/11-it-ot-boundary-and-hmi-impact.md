# ICS/OT — IT-to-OT Boundary and HMI Impact - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **it ot boundary and hmi impact** to identify unsafe or unauthorized industrial-control activity. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Industrial network telemetry normalized to CPS/ECS; parser-specific OT fields may require adjustment. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
(source.zone=/^IT$/i destination.zone=/^OT$/i) OR host.type=/^(hmi|historian|engineering)$/i
| table([@timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, network.protocol, network.bytes, event.action, host.name, user.name], limit=2000)
```

```cql
(source.zone=/^IT$/i destination.zone=/^OT$/i) OR host.type=/^(hmi|historian|engineering)$/i
| groupBy([source.ip, destination.ip, destination.zone], function=[count(as=events), sum(network.bytes, as=bytes)], limit=max)
| sort(events, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.
- Join controller and engineering-workstation results to the authoritative OT asset inventory.

# C2 — HTTP POST - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **http post** to identify covert or recurring command-and-control channels. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Normalized HTTP or proxy telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
http.request.method=/^POST$/i
| table([@timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, network.protocol, network.bytes, event.action, host.name, user.name], limit=2000)
```

```cql
http.request.method=/^POST$/i
| groupBy([source.ip, destination.ip, url.domain], function=[count(as=events), sum(network.bytes, as=bytes)], limit=max)
| sort(events, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

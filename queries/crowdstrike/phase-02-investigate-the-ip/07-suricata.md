# Suricata for this IP - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **suricata** to scope an IP lead across independent telemetry. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Normalized HTTP, TLS, or Suricata telemetry; set the `ip` parameter. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
(#event.module=suricata event.kind=alert) | source.ip=?{ip=*} OR destination.ip=?{ip=*}
| table([@timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, network.protocol, network.bytes, event.action, host.name, user.name], limit=2000)
```

```cql
(#event.module=suricata event.kind=alert) | source.ip=?{ip=*} OR destination.ip=?{ip=*}
| groupBy([source.ip, destination.ip, destination.port], function=[count(as=events), sum(network.bytes, as=bytes)], limit=max)
| sort(events, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

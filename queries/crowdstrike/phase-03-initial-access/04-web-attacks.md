# Web Attacks — Initial Access - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **web attacks** to identify how an attacker may have entered the environment. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Normalized web server or reverse-proxy telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
url.original=/(\.\.\/|union(\+|%20|\s)+select|<script|\/etc\/passwd|cmd=|powershell|%2e%2e|jndi:)/i
| table([@timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, network.protocol, network.bytes, event.action, host.name, user.name], limit=2000)
```

```cql
url.original=/(\.\.\/|union(\+|%20|\s)+select|<script|\/etc\/passwd|cmd=|powershell|%2e%2e|jndi:)/i
| groupBy([source.ip, destination.ip, url.path], function=[count(as=events), sum(network.bytes, as=bytes)], limit=max)
| sort(events, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

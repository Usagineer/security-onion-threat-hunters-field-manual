# IOC — Sigma (Playbook / detections) - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **sigma** to scope a known indicator across the estate. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon native or normalized IOC-bearing telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
rule.category=/^sigma$/i OR rule.name=?{sigma_rule=*}
| table([@timestamp, rule.name, rule.id, rule.category, event.dataset, host.name, user.name, process.name, process.command_line, source.ip, destination.ip], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.
- Replace wildcard parameter defaults with the exact case indicator.

# IOC — YARA (via Strelka file scanning) - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **yara** to scope a known indicator across the estate. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon native or normalized IOC-bearing telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
rule.category=/^yara$/i OR yara.rule.name=*
| table([@timestamp, rule.name, yara.rule.name, host.name, user.name, process.name, file.path, file.hash.sha256, event.action], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.
- Replace wildcard parameter defaults with the exact case indicator.

# IOC — File Hash - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **hash** to scope a known indicator across the estate. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon native or normalized IOC-bearing telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(ProcessRollup2|ImageHash|PeFileWritten|NewExecutableWritten|NewScriptWritten)$/
| SHA256HashData=?{sha256=*}
| table([@timestamp, #event_simpleName, aid, ContextProcessId, TargetProcessId, ImageFileName, TargetFileName, CommandLine, SHA256HashData], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.
- Replace wildcard parameter defaults with the exact case indicator.

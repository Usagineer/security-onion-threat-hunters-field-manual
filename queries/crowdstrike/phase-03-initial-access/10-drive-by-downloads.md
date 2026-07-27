# Drive-by Downloads — Initial Access - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **drive by downloads** to identify how an attacker may have entered the environment. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon file-write telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(PeFileWritten|NewExecutableWritten|NewScriptWritten|JarFileWritten|ZipFileWritten)$/
| TargetFileName=/\\(Downloads|AppData\\Local\\Temp|INetCache)\\/i
| table([@timestamp, aid, ContextProcessId, TargetFileName, SHA256HashData, FileName, Size], limit=2000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

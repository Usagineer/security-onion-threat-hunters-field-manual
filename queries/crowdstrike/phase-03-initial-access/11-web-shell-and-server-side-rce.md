# Web Shell / Server-Side RCE — Initial Access - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **web shell and server side rce** to identify how an attacker may have entered the environment. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon process telemetry on web servers. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ParentBaseFileName=/^(w3wp|httpd|nginx|apache|tomcat|java)\.exe$/i
| ImageFileName=/\\(cmd|powershell|pwsh|cscript|wscript|rundll32|whoami|net|nltest|certutil)\.exe$/i
| table([@timestamp, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData], limit=2000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

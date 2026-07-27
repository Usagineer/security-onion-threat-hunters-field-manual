# Found WinRM -> chase remote execution - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **found winrm** to continue from a confirmed lead into its surrounding activity. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon process and network telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(NetworkConnectIP4|UserLogon|ProcessRollup2)$/ event_platform=Win
| (RemotePort=/^(5985|5986)$/ OR ImageFileName=/\\(wsmprovhost|winrs|powershell|pwsh)\.exe$/i)
| table([@timestamp, #event_simpleName, aid, UserName, UserSid, RemoteAddressIP4, RemotePort, ParentBaseFileName, ImageFileName, CommandLine], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

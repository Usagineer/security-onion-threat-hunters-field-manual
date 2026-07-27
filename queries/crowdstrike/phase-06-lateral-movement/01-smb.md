# Lateral Movement — SMB - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **smb** to identify movement from one system or account to another. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon SMB and network telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(ProcessExecOnSMBFile|SmbServerShareOpenedEtw|NetworkConnectIP4)$/
| (#event_simpleName!=NetworkConnectIP4 OR RemotePort=445)
| groupBy([#event_simpleName, aid, RemoteAddressIP4], function=[count(as=events), collect([FileName, ShareName, ContextProcessId], limit=50)], limit=max)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

# Lateral Movement — RDP - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **rdp** to identify movement from one system or account to another. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon RDP and logon telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(UserLogon|ProcessExecOnRDPFile)$/ event_platform=Win
| (#event_simpleName!=UserLogon OR LogonType="10")
| groupBy([UserName, RemoteAddressIP4, aid, #event_simpleName], function=count(as=events), limit=max)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

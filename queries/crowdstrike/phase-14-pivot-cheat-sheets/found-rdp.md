# Found RDP -> chase the logon - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **found rdp** to continue from a confirmed lead into its surrounding activity. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon RDP and logon telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(UserLogon|UserLogonFailed2|ProcessExecOnRDPFile)$/ event_platform=Win
| (LogonType="10" OR #event_simpleName=ProcessExecOnRDPFile)
| UserName=?{user=*}
| table([@timestamp, #event_simpleName, aid, UserName, RemoteAddressIP4, ContextProcessId, ImageFileName, CommandLine, TargetFileName], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

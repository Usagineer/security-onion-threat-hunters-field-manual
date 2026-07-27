# Discovery — PowerShell - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **powershell discovery** to identify commands used to learn the host, users, domain, and network. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon endpoint process telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ImageFileName=/(Get-(ComputerInfo|NetIPConfiguration|NetTCPConnection|LocalUser|LocalGroup|ADUser|ADGroup|ADDomain)|Resolve-DnsName|Test-NetConnection)/i OR CommandLine=/(Get-(ComputerInfo|NetIPConfiguration|NetTCPConnection|LocalUser|LocalGroup|ADUser|ADGroup|ADDomain)|Resolve-DnsName|Test-NetConnection)/i
| table([@timestamp, aid, ComputerName, UserSid, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData], limit=2000)
```

```cql
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ImageFileName=/(Get-(ComputerInfo|NetIPConfiguration|NetTCPConnection|LocalUser|LocalGroup|ADUser|ADGroup|ADDomain)|Resolve-DnsName|Test-NetConnection)/i OR CommandLine=/(Get-(ComputerInfo|NetIPConfiguration|NetTCPConnection|LocalUser|LocalGroup|ADUser|ADGroup|ADDomain)|Resolve-DnsName|Test-NetConnection)/i
| groupBy([aid, ParentBaseFileName, ImageFileName], function=[count(as=executions), collect(CommandLine, limit=20)], limit=max)
| sort(executions, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

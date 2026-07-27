# Found beaconing -> confirm and fingerprint - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **found beaconing** to continue from a confirmed lead into its surrounding activity. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon process and network telemetry; set `aid` and `process_id`. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(NetworkConnectIP4|DnsRequest|TlsClientHello|ProcessRollup2)$/
| aid=?{aid=*}
| ContextProcessId=?{process_id=*} OR TargetProcessId=?{process_id=*}
| table([@timestamp, #event_simpleName, aid, ContextProcessId, TargetProcessId, ImageFileName, CommandLine, DomainName, RemoteAddressIP4, RemotePort, ServerName, JA3Hash], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

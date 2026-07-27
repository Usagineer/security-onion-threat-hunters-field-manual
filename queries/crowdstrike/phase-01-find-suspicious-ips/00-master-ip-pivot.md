# Master IP Pivot (run top to bottom for <IP>) - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **master ip pivot** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon endpoint telemetry; set the `ip` CQL parameter. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4|UserLogon|UserLogonFailed2|RemoteBruteForceDetectInfo|TlsClientHello)$/
| RemoteAddressIP4=?{ip=*}
| table([@timestamp, #event_simpleName, aid, UserName, ContextProcessId, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort], limit=5000)
```

```cql
#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4|UserLogon|UserLogonFailed2|RemoteBruteForceDetectInfo|TlsClientHello)$/
| RemoteAddressIP4=?{ip=*}
| groupBy([#event_simpleName, aid], function=count(as=events), limit=max)
| sort(events, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

# C2 — TLS - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **tls** to identify covert or recurring command-and-control channels. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon `TlsClientHello` telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=TlsClientHello
| groupBy([ServerName, JA3Hash, CertificateIssuer], function=[count(as=handshakes), count(aid, distinct=true, as=endpoints), collect(RemoteAddressIP4, limit=50)], limit=max)
| endpoints<=3
| sort(handshakes, order=ascending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

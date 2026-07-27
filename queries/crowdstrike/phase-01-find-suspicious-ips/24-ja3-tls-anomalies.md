# JA3 / JA3S & TLS Anomalies - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **ja3 tls anomalies** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon `TlsClientHello` or normalized TLS telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=TlsClientHello
| JA3Hash=*
| groupBy(JA3Hash, function=[count(as=handshakes), count(aid, distinct=true, as=endpoints), collect([RemoteAddressIP4, ServerName], limit=50)], limit=max)
| endpoints<=3
| sort(handshakes, order=ascending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

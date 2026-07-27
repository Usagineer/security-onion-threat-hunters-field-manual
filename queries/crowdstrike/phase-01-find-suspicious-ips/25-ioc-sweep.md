# IOC Sweep (IP / Domain / URL / Hash / JA3 / UA) - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **ioc sweep** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Normalized network telemetry and Falcon Intelligence `ioc:lookup()`. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
source.ip=* OR destination.ip=*
| ioc:lookup([source.ip, destination.ip], type="ip_address", confidenceThreshold=unverified, strict=true)
| split(ioc)
| table([@timestamp, source.ip, destination.ip, destination.port, host.name, user.name, ioc.indicator, ioc.malicious_confidence, ioc.labels], limit=2000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

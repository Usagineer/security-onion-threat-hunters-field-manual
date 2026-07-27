# IOC — Domain - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **domain** to scope a known indicator across the estate. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon native or normalized IOC-bearing telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=DnsRequest
| DomainName=?{domain=*}
| ioc:lookup(DomainName, type=domain, confidenceThreshold=unverified, strict=false)
| table([@timestamp, aid, ContextProcessId, DomainName, RequestType, ioc.malicious_confidence, ioc.labels], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.
- Replace wildcard parameter defaults with the exact case indicator.

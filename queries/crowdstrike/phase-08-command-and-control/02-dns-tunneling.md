# C2 — DNS Tunneling - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **dns tunneling** to identify covert or recurring command-and-control channels. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon `DnsRequest` telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=DnsRequest
| entropy:=shannonEntropy(DomainName)
| length:=length(DomainName)
| groupBy([DomainName, entropy, length], function=[count(as=requests), count(aid, distinct=true, as=endpoints)], limit=max)
| entropy>=3.5 length>=50
| sort(requests, order=descending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

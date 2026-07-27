# Exfiltration — Google Drive - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **google drive** to identify staging and transfer of collected data. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon `DnsRequest` telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=DnsRequest
| DomainName=/(drive\.google\.com|docs\.google\.com|googleapis\.com|googleusercontent\.com)$/i
| table([@timestamp, aid, ComputerName, ContextProcessId, DomainName, RequestType], limit=2000)
```

```cql
#event_simpleName=DnsRequest
| DomainName=/(drive\.google\.com|docs\.google\.com|googleapis\.com|googleusercontent\.com)$/i
| groupBy(DomainName, function=[count(as=requests), count(aid, distinct=true, as=endpoints)], limit=max)
| sort(endpoints, order=ascending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

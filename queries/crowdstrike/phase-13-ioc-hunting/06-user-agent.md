# IOC — User-Agent - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **user agent** to scope a known indicator across the estate. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon native or normalized IOC-bearing telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
user_agent.original=?{user_agent=*}
| groupBy([user_agent.original, source.ip, user.name, url.domain], function=[count(as=requests), collect(url.full, limit=50)], limit=max)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.
- Replace wildcard parameter defaults with the exact case indicator.

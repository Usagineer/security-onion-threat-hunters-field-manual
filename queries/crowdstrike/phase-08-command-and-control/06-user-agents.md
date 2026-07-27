# C2 — User Agents - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **user agents** to identify covert or recurring command-and-control channels. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Normalized proxy or HTTP telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
user_agent.original=*
| groupBy(user_agent.original, function=[count(as=requests), count(source.ip, distinct=true, as=sources), collect([url.domain, source.ip], limit=50)], limit=max)
| sources<=3
| sort(requests, order=ascending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

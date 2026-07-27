# IOC — URL - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **url** to scope a known indicator across the estate. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon native or normalized IOC-bearing telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
url.full=?{url=*}
| table([@timestamp, source.ip, destination.ip, host.name, user.name, process.name, http.request.method, url.full, http.response.status_code, user_agent.original], limit=5000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.
- Replace wildcard parameter defaults with the exact case indicator.

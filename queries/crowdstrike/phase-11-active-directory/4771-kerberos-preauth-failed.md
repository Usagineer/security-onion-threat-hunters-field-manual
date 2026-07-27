# Event 4771 — Kerberos Preauth Failed - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **kerberos preauth failed** to investigate Windows and Active Directory security events. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Windows Event Log normalized to CPS/ECS. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
event.code="4771"
| table([@timestamp, host.name, user.name, source.ip, event.code, event.action, event.outcome, winlog.channel, winlog.event_data], limit=2000)
| groupBy([host.name, user.name, source.ip, event.outcome], function=count(as=events), limit=max)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

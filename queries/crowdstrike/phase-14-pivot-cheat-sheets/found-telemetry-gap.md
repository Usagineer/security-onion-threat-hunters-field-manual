# Found a telemetry gap -> test for defense impairment - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **found telemetry gap** to continue from a confirmed lead into its surrounding activity. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon sensor health telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(AgentOnline|SensorHeartbeat)$/
| groupBy(aid, function=[max(@timestamp, as=lastSeen), collect([ComputerName, AgentVersion], limit=5)], limit=max)
| sort(lastSeen, order=ascending, limit=1000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

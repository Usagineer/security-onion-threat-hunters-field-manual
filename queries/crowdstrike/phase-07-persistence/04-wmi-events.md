# Persistence — WMI Event Subscriptions - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **wmi events** to identify mechanisms that preserve attacker access. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon WMI telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=/^(WmiFilterConsumerBinding|WmiEventConsumer|WmiEventFilter|WmiCreateProcess)$/
| groupBy([#event_simpleName, aid], function=[count(as=events), collect([ConsumerName, FilterName, CommandLine, ImageFileName], limit=50)], limit=max)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

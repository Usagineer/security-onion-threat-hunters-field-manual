# Email — Initial Access - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **email** to identify how an attacker may have entered the environment. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Normalized secure-email-gateway telemetry. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
event.category=email
| (email.attachments[].file.name=/\.(iso|img|lnk|js|vbs|hta|chm|xll|one|zip|rar)$/i OR url.full=* OR event.outcome=/fail|blocked/i)
| table([@timestamp, source.ip, email.from.address, email.to.address, email.subject, email.attachments[].file.name, url.full, event.action, event.outcome], limit=2000)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

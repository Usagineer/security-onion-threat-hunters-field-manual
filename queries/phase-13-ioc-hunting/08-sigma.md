# IOC — Sigma (Playbook / detections)

```
tags:*sigma*
```

```
rule.name:"<sigma_rule_name>"
```

```
event.module:soc AND rule.uuid:"<sigma_rule_uuid>"
```

## What this does

Searches Security Onion telemetry for the specified indicator type: Sigma. Use the results with the surrounding host, user, time, and network context before escalating.

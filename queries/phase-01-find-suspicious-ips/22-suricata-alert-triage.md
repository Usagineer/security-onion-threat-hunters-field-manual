# Suricata Alert Triage

```
event.module:suricata | groupby rule.name
```

```
event.module:suricata AND event.severity_label:high | groupby rule.name source.ip destination.ip
```

```
event.module:suricata AND event.severity:1 | groupby rule.name source.ip destination.ip
```

```
network.community_id:"<value from the alert>"
```

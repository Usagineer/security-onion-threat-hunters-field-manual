# Suricata for this IP

```
event.module:suricata AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.module:suricata AND (source.ip:<IP> OR destination.ip:<IP>) | groupby rule.name rule.category
```

```
event.module:suricata AND (source.ip:<IP> OR destination.ip:<IP>) AND event.severity:1
```

## What this does

Pivots through available network, alert, and endpoint evidence for Suricata. Use the results with the surrounding host, user, time, and network context before escalating.

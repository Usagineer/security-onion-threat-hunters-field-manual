# New / First-Seen External IP

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.ip
```

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby source.ip destination.port destination.as.organization.name
```

## What this does

Finds and prioritizes suspicious network behavior associated with New First Seen External Ip. Use the results with the surrounding host, user, time, and network context before escalating.

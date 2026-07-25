# Long-Lived Connections

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" AND event.duration:>3600000000000 | groupby source.ip destination.ip destination.port
```

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby destination.as.organization.name network.protocol
```

## What this does

Finds and prioritizes suspicious network behavior associated with Long Lived Connections. Use the results with the surrounding host, user, time, and network context before escalating.

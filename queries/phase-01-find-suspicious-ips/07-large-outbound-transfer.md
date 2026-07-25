# Large Outbound Transfer (Exfil)

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" AND source.bytes:>10000000 | groupby source.ip destination.ip
```

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<DEST> | groupby destination.as.organization.name destination.port network.protocol
```

## What this does

Finds and prioritizes suspicious network behavior associated with Large Outbound Transfer. Use the results with the surrounding host, user, time, and network context before escalating.

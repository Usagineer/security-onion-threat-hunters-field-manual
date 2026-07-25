# RDP Reach & Exposure

```
event.dataset:zeek.conn AND destination.port:3389 | groupby source.ip destination.ip
```

```
event.dataset:zeek.conn AND destination.port:3389 AND NOT source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8"
```

```
event.dataset:zeek.conn AND destination.port:3389 AND source.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

## What this does

Finds and prioritizes suspicious network behavior associated with Rdp Reach Exposure. Use the results with the surrounding host, user, time, and network context before escalating.

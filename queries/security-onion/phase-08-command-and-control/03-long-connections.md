# C2 — Long Connections

## What this does

Looks for command-and-control behavior involving Long Connections. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" AND event.duration:>3600000000000 | groupby source.ip destination.ip destination.port
```

```
event.dataset:zeek.conn AND event.duration:>3600000000000 | groupby destination.as.organization.name
```

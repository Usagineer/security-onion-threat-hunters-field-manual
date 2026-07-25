# C2 — Beaconing

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<DEST>
```

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<DEST> | groupby network.bytes destination.port
```

## What this does

Looks for command-and-control behavior involving Beaconing. Use the results with the surrounding host, user, time, and network context before escalating.

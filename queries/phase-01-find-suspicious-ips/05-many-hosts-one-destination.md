# Many Hosts -> One Destination (C2 Convergence)

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" | groupby destination.ip
```

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby destination.as.organization.name destination.geo.country_name destination.port
```

```
event.dataset:zeek.dns AND dns.answers:<IP>
```

## What this does

Finds and prioritizes suspicious network behavior associated with Many Hosts One Destination. Use the results with the surrounding host, user, time, and network context before escalating.

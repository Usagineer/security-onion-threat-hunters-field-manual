# Connections to Rare Countries

## What this does

Finds and prioritizes suspicious network behavior associated with Rare Countries. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.geo.country_name
```

```
event.dataset:zeek.conn AND destination.geo.country_name:"<Country>" | groupby destination.ip source.ip destination.as.organization.name
```

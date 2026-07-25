# Rare Destination IP

## What this does

Finds and prioritizes suspicious network behavior associated with Rare Destination Ip. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" AND NOT destination.ip:"172.16.0.0/12" AND NOT destination.ip:"192.168.0.0/16" AND NOT destination.ip:"169.254.0.0/16" AND NOT destination.ip:"224.0.0.0/4" AND NOT destination.ip:"255.255.255.255" AND NOT destination.ip:"fe80::/10" AND NOT destination.ip:"ff00::/8" | groupby destination.ip
```

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby source.ip destination.port network.protocol connection.state
```

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby destination.as.organization.name destination.geo.country_name
```

```
source.ip:<IP> OR destination.ip:<IP>
```

## Refined + ASN enrichment — triage rare vs. known CDN/cloud

Adds ownership context only after selecting a candidate, so it does not fragment
the initial rarity count. A rare destination is a lead, not a verdict; corroborate
with protocol, timing, alerts, and endpoint telemetry.

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby destination.as.organization.name source.ip destination.port
```
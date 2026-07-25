# Cloud & VPS Providers

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.as.organization.name
```

```
event.dataset:zeek.conn AND destination.as.organization.name:*DigitalOcean* | groupby destination.ip source.ip destination.port
```

## What this does

Finds and prioritizes suspicious network behavior associated with Cloud Vps Providers. Use the results with the surrounding host, user, time, and network context before escalating.

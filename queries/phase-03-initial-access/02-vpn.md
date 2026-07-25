# VPN — Initial Access

```
event.dataset:zeek.conn AND destination.port:(1194 OR 500 OR 4500 OR 1723) | groupby source.ip destination.ip
```

```
event.module:suricata AND rule.name:*VPN* | groupby source.ip destination.ip
```

```
event.category:authentication | groupby source.ip source.geo.country_name user.name
```

## What this does

Looks for signs of initial-access activity involving Vpn. Use the results with the surrounding host, user, time, and network context before escalating.

# Rare Destination IP

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" AND NOT destination.ip:"172.16.0.0/12" AND NOT destination.ip:"192.168.0.0/16" | groupby destination.ip
```

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby source.ip destination.port destination.as.organization.name
```

```
source.ip:<IP> OR destination.ip:<IP>
```

## Refined + ASN enrichment — triage rare vs. known CDN/cloud

Adds the owning org so you can ignore Amazon / Google / Microsoft / Fastly / Akamai / Cloudflare at a glance and pivot only on unexplained hosting/VPS or residential ISPs. Sort ascending; the count-1 rows on a hosting ASN are the leads.

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" AND NOT destination.ip:"172.16.0.0/12" AND NOT destination.ip:"192.168.0.0/16" AND NOT destination.ip:"224.0.0.0/4" AND NOT destination.ip:"255.255.255.255" AND NOT destination.ip:"169.254.0.0/16" AND NOT destination.ip:"fe80::/10" AND NOT destination.ip:"ff00::/8" | groupby destination.ip destination.as.organization.name
```

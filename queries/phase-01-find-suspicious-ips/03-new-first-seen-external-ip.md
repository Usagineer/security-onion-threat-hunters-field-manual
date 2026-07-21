# New / First-Seen External IP

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.ip
```

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby source.ip destination.port destination.as.organization.name
```

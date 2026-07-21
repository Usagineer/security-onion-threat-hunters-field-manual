# RDP — Initial Access

```
event.dataset:zeek.conn AND destination.port:3389 AND NOT source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8"
```

```
event.code:4625 AND winlog.event_data.LogonType:10 | groupby source.ip destination.ip
```

```
event.code:4625 AND winlog.event_data.LogonType:10 | groupby source.ip winlog.event_data.TargetUserName
```

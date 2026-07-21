# Lateral Movement — RDP

```
event.dataset:zeek.conn AND destination.port:3389 AND source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

```
event.code:4624 AND winlog.event_data.LogonType:10 | groupby source.ip winlog.event_data.TargetUserName destination.ip
```

```
event.code:4778 | groupby winlog.event_data.AccountName source.ip
```

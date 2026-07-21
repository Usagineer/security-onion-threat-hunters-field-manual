# Event 4625 — Failed Logon

```
event.code:4625 | groupby source.ip winlog.event_data.TargetUserName
```

```
event.code:4625 | groupby winlog.event_data.TargetUserName host.name
```

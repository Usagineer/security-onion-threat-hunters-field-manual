# Event 4624 — Successful Logon

```
event.code:4624 | groupby winlog.event_data.LogonType winlog.event_data.TargetUserName source.ip
```

```
event.code:4624 AND winlog.event_data.LogonType:(3 OR 10) | groupby source.ip winlog.event_data.TargetUserName host.name
```

# Event 4625 — Failed Logon

## What this does

Reviews Windows and Active Directory event evidence involving Failed Logon. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4625 | groupby source.ip winlog.event_data.TargetUserName
```

```
event.code:4625 | groupby winlog.event_data.TargetUserName host.name
```

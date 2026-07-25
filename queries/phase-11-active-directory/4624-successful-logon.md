# Event 4624 — Successful Logon

## What this does

Reviews Windows and Active Directory event evidence involving Successful Logon. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4624 | groupby winlog.event_data.LogonType winlog.event_data.TargetUserName source.ip
```

```
event.code:4624 AND winlog.event_data.LogonType:(3 OR 10) | groupby source.ip winlog.event_data.TargetUserName host.name
```

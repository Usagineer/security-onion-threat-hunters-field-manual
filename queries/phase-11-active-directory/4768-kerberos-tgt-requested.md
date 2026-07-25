# Event 4768 — Kerberos Tgt Requested

```
event.code:4768 | groupby winlog.event_data.TargetUserName source.ip
```

```
event.code:4768 AND winlog.event_data.PreAuthType:0
```

## What this does

Reviews Windows and Active Directory event evidence involving Kerberos Tgt Requested. Use the results with the surrounding host, user, time, and network context before escalating.

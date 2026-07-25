# Event 4771 — Kerberos Preauth Failed

```
event.code:4771 | groupby winlog.event_data.TargetUserName source.ip
```

```
event.code:4771 | groupby source.ip
```

## What this does

Reviews Windows and Active Directory event evidence involving Kerberos Preauth Failed. Use the results with the surrounding host, user, time, and network context before escalating.

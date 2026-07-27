# Event 4720 — User Account Created

## What this does

Reviews Windows and Active Directory event evidence involving User Account Created. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4720 | groupby host.name winlog.event_data.TargetUserName winlog.event_data.SubjectUserName
```

```
event.code:(4720 OR 4722 OR 4724 OR 4738)
```

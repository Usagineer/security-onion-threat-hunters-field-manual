# Event 4732 — Member Added Local Group

```
event.code:4732 | groupby host.name winlog.event_data.TargetUserName winlog.event_data.MemberName
```

```
event.code:4732 AND winlog.event_data.TargetUserName:*Administrators*
```

## What this does

Reviews Windows and Active Directory event evidence involving Member Added Local Group. Use the results with the surrounding host, user, time, and network context before escalating.

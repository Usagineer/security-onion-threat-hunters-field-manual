# Event 4728 — Member Added Global Group

```
event.code:4728 | groupby winlog.event_data.TargetUserName winlog.event_data.MemberName
```

```
event.code:(4728 OR 4756) AND winlog.event_data.TargetUserName:*admin*
```

## What this does

Reviews Windows and Active Directory event evidence involving Member Added Global Group. Use the results with the surrounding host, user, time, and network context before escalating.

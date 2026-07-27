# Event 4672 — Special Privileges

## What this does

Reviews Windows and Active Directory event evidence involving Special Privileges. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4672 | groupby winlog.event_data.SubjectUserName host.name
```

```
event.code:4672 AND NOT winlog.event_data.SubjectUserName:(*$ OR SYSTEM)
```

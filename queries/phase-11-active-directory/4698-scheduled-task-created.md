# Event 4698 — Scheduled Task Created

## What this does

Reviews Windows and Active Directory event evidence involving Scheduled Task Created. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4698 | groupby host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName
```

```
event.code:(4698 OR 4699 OR 4700 OR 4702)
```

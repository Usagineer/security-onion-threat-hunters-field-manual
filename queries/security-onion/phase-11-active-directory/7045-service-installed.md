# Event 7045 — Service Installed

## What this does

Reviews Windows and Active Directory event evidence involving Service Installed. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:7045 | groupby host.name winlog.event_data.ServiceName winlog.event_data.ImagePath
```

```
event.code:7045 AND winlog.event_data.ImagePath:(*powershell* OR *cmd* OR *%COMSPEC% OR *\\* OR *ADMIN$*)
```

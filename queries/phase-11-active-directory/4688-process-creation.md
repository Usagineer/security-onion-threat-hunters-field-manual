# Event 4688 — Process Creation

## What this does

Reviews Windows and Active Directory event evidence involving Process Creation. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4688 | groupby host.name winlog.event_data.NewProcessName
```

```
event.code:4688 AND winlog.event_data.NewProcessName:(*powershell* OR *cmd* OR *wscript* OR *mshta* OR *rundll32*)
```

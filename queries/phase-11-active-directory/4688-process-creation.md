# Event 4688 — Process Creation

```
event.code:4688 | groupby host.name winlog.event_data.NewProcessName
```

```
event.code:4688 AND winlog.event_data.NewProcessName:(*powershell* OR *cmd* OR *wscript* OR *mshta* OR *rundll32*)
```

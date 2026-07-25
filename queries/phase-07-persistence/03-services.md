# Persistence — Services

```
event.code:7045 | groupby host.name winlog.event_data.ServiceName winlog.event_data.ImagePath
```

```
event.category:process AND process.name:"sc.exe" AND process.command_line:*create*
```

```
event.category:registry AND registry.path:*System*CurrentControlSet*Services*
```

## What this does

Looks for persistence mechanisms involving Services. Use the results with the surrounding host, user, time, and network context before escalating.

# Persistence — Registry Run Keys

## What this does

Looks for persistence mechanisms involving Registry Run Keys. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:registry AND registry.path:(*CurrentVersion*Run* OR *CurrentVersion*RunOnce*)
```

```
event.category:process AND process.name:"reg.exe" AND process.command_line:(*add* AND *Run*)
```

```
event.code:13 AND winlog.event_data.TargetObject:(*CurrentVersion*Run*)
```

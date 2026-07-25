# Persistence — Scheduled Tasks

## What this does

Looks for persistence mechanisms involving Scheduled Tasks. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4698 | groupby host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName
```

```
event.category:process AND process.name:"schtasks.exe" AND process.command_line:*/create*
```

```
event.category:registry AND registry.path:*Schedule*TaskCache*Tree*
```

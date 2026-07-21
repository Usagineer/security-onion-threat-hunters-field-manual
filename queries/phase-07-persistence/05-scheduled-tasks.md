# Persistence — Scheduled Tasks

```
event.code:4698 | groupby host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName
```

```
event.category:process AND process.name:"schtasks.exe" AND process.command_line:*/create*
```

```
event.category:registry AND registry.path:*Schedule*TaskCache*Tree*
```

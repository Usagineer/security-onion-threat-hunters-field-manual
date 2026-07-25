# Lateral Movement — Scheduled Tasks

```
event.category:process AND process.name:"schtasks.exe" AND process.command_line:(*/create* AND */s*)
```

```
event.code:4698 | groupby host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName
```

```
event.dataset:zeek.dce_rpc AND dce_rpc.endpoint:("atsvc" OR "ITaskSchedulerService")
```

## What this does

Looks for lateral-movement behavior involving Scheduled Tasks. Use the results with the surrounding host, user, time, and network context before escalating.

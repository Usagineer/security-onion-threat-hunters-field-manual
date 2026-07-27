# Lateral Movement — PsExec

## What this does

Looks for lateral-movement behavior involving Psexec. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:7045 AND winlog.event_data.ServiceName:*PSEXESVC*
```

```
event.category:process AND process.name:("psexec.exe" OR "psexesvc.exe" OR "paexec.exe")
```

```
event.category:process AND process.parent.name:"PSEXESVC.exe"
```

```
event.dataset:zeek.dce_rpc AND dce_rpc.endpoint:"svcctl"
```

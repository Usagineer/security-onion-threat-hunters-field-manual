# Lateral Movement — Remote Services

```
event.code:7045 | groupby host.name winlog.event_data.ServiceName winlog.event_data.ImagePath
```

```
event.category:process AND process.name:"sc.exe" AND process.command_line:(*create* OR *\\*)
```

```
event.dataset:zeek.dce_rpc AND dce_rpc.endpoint:"svcctl"
```

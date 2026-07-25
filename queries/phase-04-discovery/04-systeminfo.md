# Discovery — systeminfo

```
event.category:process AND event.type:start AND process.name:"systeminfo.exe"
```

```
event.category:process AND event.type:start AND process.name:("wmic.exe" OR "systeminfo.exe") AND process.command_line:(*os get* OR *computersystem*)
```

## What this does

Looks for host or network discovery activity involving Systeminfo. Use the results with the surrounding host, user, time, and network context before escalating.

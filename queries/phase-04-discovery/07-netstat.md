# Discovery — netstat

```
event.category:process AND event.type:start AND process.name:"netstat.exe"
```

```
event.category:process AND event.type:start AND process.command_line:*netstat*
```

## What this does

Looks for host or network discovery activity involving Netstat. Use the results with the surrounding host, user, time, and network context before escalating.

# Discovery — net user / net group

## What this does

Looks for host or network discovery activity involving Net User Group. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:process AND event.type:start AND process.name:("net.exe" OR "net1.exe")
```

```
event.category:process AND event.type:start AND process.command_line:(*net user* OR *net group* OR *net localgroup* OR *domain admins*) | groupby host.name process.command_line
```

```
event.category:process AND event.type:start AND process.command_line:(*net accounts* OR *net view*)
```

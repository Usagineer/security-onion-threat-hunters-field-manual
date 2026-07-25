# Discovery — hostname / ipconfig

```
event.category:process AND event.type:start AND process.name:("hostname.exe" OR "ipconfig.exe")
```

```
event.category:process AND event.type:start AND process.command_line:(*ipconfig* OR *hostname*) | groupby host.name process.parent.name
```

## What this does

Looks for host or network discovery activity involving Hostname Ipconfig. Use the results with the surrounding host, user, time, and network context before escalating.

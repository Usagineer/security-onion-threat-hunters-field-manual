# Discovery — whoami

```
event.category:process AND event.type:start AND process.name:"whoami.exe"
```

```
event.category:process AND event.type:start AND process.command_line:*whoami* | groupby host.name process.parent.name
```

## What this does

Looks for host or network discovery activity involving Whoami. Use the results with the surrounding host, user, time, and network context before escalating.

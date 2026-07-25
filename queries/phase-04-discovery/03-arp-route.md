# Discovery — arp / route

```
event.category:process AND event.type:start AND process.name:("arp.exe" OR "route.exe")
```

```
event.category:process AND event.type:start AND process.command_line:(*arp -a* OR *route print*)
```

## What this does

Looks for host or network discovery activity involving Arp Route. Use the results with the surrounding host, user, time, and network context before escalating.

# Discovery — nltest

```
event.category:process AND event.type:start AND process.name:"nltest.exe"
```

```
event.category:process AND event.type:start AND process.command_line:(*dclist* OR *domain_trusts* OR *dsgetdc*)
```

## What this does

Looks for host or network discovery activity involving Nltest. Use the results with the surrounding host, user, time, and network context before escalating.

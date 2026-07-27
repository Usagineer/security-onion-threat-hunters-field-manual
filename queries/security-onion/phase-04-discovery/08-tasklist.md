# Discovery — tasklist

## What this does

Looks for host or network discovery activity involving Tasklist. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:process AND event.type:start AND process.name:("tasklist.exe" OR "qprocess.exe")
```

```
event.category:process AND event.type:start AND process.command_line:(*tasklist* OR *tasklist /svc*)
```

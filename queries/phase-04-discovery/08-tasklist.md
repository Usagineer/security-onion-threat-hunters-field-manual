# Discovery — tasklist

```
event.category:process AND event.type:start AND process.name:("tasklist.exe" OR "qprocess.exe")
```

```
event.category:process AND event.type:start AND process.command_line:(*tasklist* OR *tasklist /svc*)
```

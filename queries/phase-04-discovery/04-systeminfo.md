# Discovery — systeminfo

```
event.category:process AND event.type:start AND process.name:"systeminfo.exe"
```

```
event.category:process AND event.type:start AND process.name:("wmic.exe" OR "systeminfo.exe") AND process.command_line:(*os get* OR *computersystem*)
```

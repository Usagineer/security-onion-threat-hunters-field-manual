# Discovery — hostname / ipconfig

```
event.category:process AND event.type:start AND process.name:("hostname.exe" OR "ipconfig.exe")
```

```
event.category:process AND event.type:start AND process.command_line:(*ipconfig* OR *hostname*) | groupby host.name process.parent.name
```

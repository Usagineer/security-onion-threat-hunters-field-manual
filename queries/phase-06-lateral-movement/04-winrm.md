# Lateral Movement — WinRM

```
event.dataset:zeek.conn AND destination.port:(5985 OR 5986) AND source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

```
event.category:process AND process.parent.name:"wsmprovhost.exe"
```

```
event.category:process AND process.name:("powershell.exe" OR "cmd.exe") AND process.parent.name:"wsmprovhost.exe"
```

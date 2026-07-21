# MSSQL — Initial Access

```
event.dataset:zeek.conn AND destination.port:1433 | groupby source.ip destination.ip
```

```
event.dataset:zeek.conn AND destination.port:1433 AND NOT source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8"
```

```
event.category:process AND process.parent.name:"sqlservr.exe" AND process.name:("cmd.exe" OR "powershell.exe")
```

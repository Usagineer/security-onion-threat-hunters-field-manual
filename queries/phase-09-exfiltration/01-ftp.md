# Exfiltration — FTP

```
event.dataset:zeek.conn AND destination.port:21 AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

```
event.dataset:zeek.ftp AND ftp.command:"STOR" | groupby source.ip destination.ip ftp.arg
```

## What this does

Looks for collection or exfiltration behavior involving Ftp. Use the results with the surrounding host, user, time, and network context before escalating.

# Exfiltration — SCP

```
event.dataset:zeek.conn AND destination.port:22 AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip source.bytes
```

```
event.category:process AND process.name:("scp.exe" OR "pscp.exe" OR "sftp.exe") AND process.command_line:*
```

## What this does

Looks for collection or exfiltration behavior involving Scp. Use the results with the surrounding host, user, time, and network context before escalating.

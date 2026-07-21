# Exfiltration — SFTP

```
event.dataset:zeek.conn AND destination.port:22 AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" AND source.bytes:>10000000 | groupby source.ip destination.ip
```

```
event.dataset:zeek.ssh AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip ssh.client
```

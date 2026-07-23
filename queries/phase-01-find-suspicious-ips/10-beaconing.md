# Beaconing (Regular Interval)

```
event.dataset:zeek.conn | groupby source.ip destination.ip destination.port
```

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<DEST>
```

```
event.dataset:zeek.conn AND ((source.ip:<HOST> AND destination.ip:<DEST>) OR (source.ip:<DEST> AND destination.ip:<HOST>)) | groupby source.ip destination.ip destination.port connection.state network.bytes
```

Do not exclude internal destinations: an attacker-controlled internal host can
act as a handler or staging server. Repeated connections to a small fixed set of
pairs indicate persistent C2 or retries, not necessarily a scan.
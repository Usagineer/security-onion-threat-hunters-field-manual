# Beaconing (Regular Interval)

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<DEST>
```

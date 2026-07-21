# One Host -> Many Ports (Port Scan)

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" | groupby source.ip destination.port
```

```
event.dataset:zeek.conn AND source.ip:<IP> AND connection.state:("S0" OR "REJ" OR "RSTO")
```

```
event.dataset:zeek.notice AND source.ip:<IP>
```

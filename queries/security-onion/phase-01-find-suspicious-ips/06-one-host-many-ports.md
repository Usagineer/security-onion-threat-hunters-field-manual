# One Host -> Many Ports (Port Scan)

## What this does

Finds and prioritizes suspicious network behavior associated with One Host Many Ports. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" | groupby source.ip destination.port
```

```
event.dataset:zeek.conn AND source.ip:<IP> AND connection.state:("S0" OR "REJ" OR "RSTO")
```

```
event.dataset:zeek.notice AND source.ip:<IP>
```

# Servers / IoT Talking Directly to the Internet

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.port
```

```
source.ip:<SERVER_IP> AND NOT destination.ip:"10.0.0.0/8"
```

## What this does

Finds and prioritizes suspicious network behavior associated with Servers Iot To Internet. Use the results with the surrounding host, user, time, and network context before escalating.

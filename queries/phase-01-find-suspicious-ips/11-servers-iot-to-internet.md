# Servers / IoT Talking Directly to the Internet

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.port
```

```
source.ip:<SERVER_IP> AND NOT destination.ip:"10.0.0.0/8"
```

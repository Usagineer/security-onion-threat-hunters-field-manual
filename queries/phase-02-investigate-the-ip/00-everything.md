# Everything for this IP

```
source.ip:<IP> OR destination.ip:<IP>
```

```
(source.ip:<IP> OR destination.ip:<IP>) | groupby network.protocol destination.port
```

```
(source.ip:<IP> OR destination.ip:<IP>) | groupby event.dataset
```

## What this does

Pivots through available network, alert, and endpoint evidence for Everything. Use the results with the surrounding host, user, time, and network context before escalating.

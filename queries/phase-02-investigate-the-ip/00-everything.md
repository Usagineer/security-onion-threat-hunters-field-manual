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

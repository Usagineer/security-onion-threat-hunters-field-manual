# Large Inbound Transfer (Staging / Download)

```
event.dataset:zeek.conn AND destination.ip:"10.0.0.0/8" AND NOT source.ip:"10.0.0.0/8" AND destination.bytes:>10000000 | groupby destination.ip source.ip
```

```
event.dataset:zeek.files AND destination.ip:<INTERNAL_HOST>
```

```
event.dataset:zeek.http AND destination.ip:<EXTERNAL_IP> AND source.ip:<INTERNAL_HOST>
```

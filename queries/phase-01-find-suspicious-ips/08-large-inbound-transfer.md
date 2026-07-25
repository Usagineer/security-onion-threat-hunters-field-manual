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

## What this does

Finds and prioritizes suspicious network behavior associated with Large Inbound Transfer. Use the results with the surrounding host, user, time, and network context before escalating.

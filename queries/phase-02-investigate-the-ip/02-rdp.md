# RDP for this IP

```
event.dataset:zeek.conn AND destination.port:3389 AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.dataset:zeek.rdp AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.code:4624 AND winlog.event_data.LogonType:10 AND (source.ip:<IP> OR host.ip:<IP>)
```

## What this does

Pivots through available network, alert, and endpoint evidence for Rdp. Use the results with the surrounding host, user, time, and network context before escalating.

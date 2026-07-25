# TLS for this IP

## What this does

Pivots through available network, alert, and endpoint evidence for Tls. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.ssl AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.dataset:zeek.ssl AND (source.ip:<IP> OR destination.ip:<IP>) | groupby tls.client.server_name
```

```
event.dataset:zeek.ssl AND (source.ip:<IP> OR destination.ip:<IP>) | groupby tls.client.ja3 tls.server.ja3s
```

```
event.dataset:zeek.x509 AND (source.ip:<IP> OR destination.ip:<IP>)
```

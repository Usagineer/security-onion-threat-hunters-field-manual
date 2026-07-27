# C2 — TLS

## What this does

Looks for command-and-control behavior involving Tls. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.ssl AND (NOT tls.client.server_name:* OR tls.client.server_name:"") AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

```
event.dataset:zeek.x509 AND x509.certificate.issuer:*self* | groupby source.ip destination.ip
```

```
event.dataset:zeek.ssl AND tls.version:("TLSv10" OR "TLSv11" OR "SSLv3") | groupby source.ip destination.ip
```

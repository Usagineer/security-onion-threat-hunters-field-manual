# C2 — Rare Domains

```
event.dataset:zeek.dns | groupby dns.question.name
```

```
event.dataset:zeek.ssl | groupby tls.client.server_name
```

```
event.dataset:zeek.http | groupby url.domain
```

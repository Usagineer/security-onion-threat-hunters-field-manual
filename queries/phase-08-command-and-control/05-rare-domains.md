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

## What this does

Looks for command-and-control behavior involving Rare Domains. Use the results with the surrounding host, user, time, and network context before escalating.

# C2 — HTTP POST

## What this does

Looks for command-and-control behavior involving Http Post. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.http AND http.request.method:POST AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip url.domain
```

```
event.dataset:zeek.http AND http.request.method:POST AND NOT destination.ip:"10.0.0.0/8" AND source.bytes:>100000 | groupby source.ip destination.ip
```

```
event.dataset:zeek.http AND http.request.method:POST AND NOT http.request.method:GET | groupby url.domain user_agent.original
```

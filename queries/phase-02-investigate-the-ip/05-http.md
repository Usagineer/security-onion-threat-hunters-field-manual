# HTTP for this IP

## What this does

Pivots through available network, alert, and endpoint evidence for Http. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.http AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.dataset:zeek.http AND (source.ip:<IP> OR destination.ip:<IP>) | groupby url.domain http.request.method
```

```
event.dataset:zeek.http AND (source.ip:<IP> OR destination.ip:<IP>) | groupby user_agent.original
```

```
event.dataset:zeek.http AND (source.ip:<IP> OR destination.ip:<IP>) | groupby url.original http.response.status_code
```

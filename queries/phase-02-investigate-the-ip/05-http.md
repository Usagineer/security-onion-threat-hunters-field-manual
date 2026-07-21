# HTTP for this IP

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

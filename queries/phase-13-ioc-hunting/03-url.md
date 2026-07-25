# IOC — URL

## What this does

Searches Security Onion telemetry for the specified indicator type: Url. Use the results with the surrounding host, user, time, and network context before escalating.

```
url.original:*<ioc_path>* OR url.domain:*<ioc_domain>*
```

```
event.dataset:zeek.http AND url.original:*<ioc_path>* | groupby source.ip destination.ip
```

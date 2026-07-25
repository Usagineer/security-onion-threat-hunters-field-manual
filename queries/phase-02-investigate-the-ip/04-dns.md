# DNS for this IP

## What this does

Pivots through available network, alert, and endpoint evidence for Dns. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.dns AND (source.ip:<IP> OR dns.answers:<IP>)
```

```
event.dataset:zeek.dns AND source.ip:<IP> | groupby dns.question.name
```

```
event.dataset:zeek.dns AND dns.answers:<IP> | groupby dns.question.name
```

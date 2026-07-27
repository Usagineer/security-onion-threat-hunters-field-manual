# Rogue / External DNS Servers

## What this does

Finds and prioritizes suspicious network behavior associated with Rogue External Dns. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.dns AND NOT destination.ip:("<DNS1>" OR "<DNS2>") AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

```
event.dataset:zeek.dns AND source.ip:<HOST> AND destination.ip:<EXTERNAL_RESOLVER> | groupby dns.question.name
```

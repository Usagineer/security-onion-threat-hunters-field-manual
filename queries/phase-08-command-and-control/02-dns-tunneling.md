# C2 — DNS Tunneling

```
event.dataset:zeek.dns | groupby dns.question.name
```

```
event.dataset:zeek.dns AND dns.question.type_name:(TXT OR NULL OR CNAME) | groupby source.ip dns.question.name
```

```
event.dataset:zeek.dns AND source.ip:<HOST> | groupby dns.question.name
```

```
event.dataset:zeek.dns AND dns.question.name:/.{50,}/
```

## What this does

Looks for command-and-control behavior involving Dns Tunneling. Use the results with the surrounding host, user, time, and network context before escalating.

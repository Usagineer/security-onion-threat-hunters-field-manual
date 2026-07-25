# Dynamic DNS

## What this does

Finds and prioritizes suspicious network behavior associated with Dynamic Dns. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.dns AND dns.question.name:(*duckdns.org OR *no-ip.com OR *ddns.net OR *hopto.org OR *sytes.net OR *zapto.org OR *myftp.org OR *serveo.net OR *ngrok.io)
```

```
event.dataset:zeek.dns AND dns.question.name:*duckdns.org | groupby source.ip dns.question.name dns.answers
```

```
source.ip:<HOST> OR destination.ip:<RESOLVED_IP>
```

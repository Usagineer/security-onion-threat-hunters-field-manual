# Found suspicious DNS -> chase resolution and C2

## What this does

Provides the next investigative pivots after finding Dns. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.dns AND dns.question.name:*<domain>* | groupby source.ip dns.answers
```

```
event.dataset:zeek.conn AND destination.ip:<RESOLVED_IP> | groupby source.ip destination.port
```

```
event.dataset:zeek.ssl AND tls.client.server_name:*<domain>* | groupby source.ip tls.client.ja3
```

```
event.module:suricata AND (dns.question.name:*<domain>* OR destination.ip:<RESOLVED_IP>)
```

# Found suspicious DNS -> chase resolution and C2

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

# JA3 / JA3S & TLS Anomalies

```
event.dataset:zeek.ssl | groupby tls.client.ja3
```

```
event.dataset:zeek.ssl AND tls.client.ja3:"<ja3hash>" | groupby source.ip destination.ip tls.client.server_name
```

```
event.dataset:zeek.ssl AND (tls.client.server_name:"" OR NOT tls.client.server_name:*) | groupby source.ip destination.ip
```

## What this does

Finds and prioritizes suspicious network behavior associated with Ja3 Tls Anomalies. Use the results with the surrounding host, user, time, and network context before escalating.

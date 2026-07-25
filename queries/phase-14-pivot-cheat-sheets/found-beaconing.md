# Found beaconing -> confirm and fingerprint

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<DEST>
```

```
event.dataset:zeek.ssl AND source.ip:<HOST> AND destination.ip:<DEST> | groupby tls.client.ja3 tls.client.server_name
```

```
event.dataset:zeek.http AND source.ip:<HOST> AND destination.ip:<DEST> | groupby url.original user_agent.original
```

```
event.module:suricata AND (source.ip:<HOST> OR destination.ip:<DEST>)
```

```
event.module:endpoint AND event.category:network AND host.ip:<HOST> AND destination.ip:<DEST> | groupby process.name
```

## What this does

Provides the next investigative pivots after finding Beaconing. Use the results with the surrounding host, user, time, and network context before escalating.

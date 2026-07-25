# Lateral Movement — Valid-Account Spread

> UNVERIFIED: Validate Windows event field mappings and select the appropriate internal ranges.

```
event.code:4624 AND winlog.event_data.LogonType:(3 OR 10) AND winlog.event_data.TargetUserName:<ACCOUNT> | groupby source.ip host.name winlog.event_data.LogonType
```

```
event.dataset:zeek.conn AND source.ip:<SOURCE_HOST> AND destination.port:(22 OR 3389 OR 445 OR 5985 OR 5986) | groupby destination.ip destination.port
```

```
event.code:4625 AND winlog.event_data.TargetUserName:<ACCOUNT> | groupby source.ip host.name winlog.event_data.LogonType
```

Scope by account *and* source host. A successful remote logon is not enough by
itself: look for a new source-to-destination relationship, multiple target hosts,
failures preceding success, or post-logon process execution.

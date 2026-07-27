# ICS/OT — Unauthorized Controllers

## What this does

Reviews ICS/OT communications and impact-related activity involving Unauthorized Controllers. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.conn AND destination.port:(102 OR 502 OR 44818 OR 20000 OR 4840) | groupby source.ip
```

```
event.dataset:zeek.conn AND destination.port:(102 OR 502 OR 44818 OR 20000 OR 4840) AND NOT source.ip:<OT_ALLOWLIST> | groupby source.ip destination.ip destination.port
```

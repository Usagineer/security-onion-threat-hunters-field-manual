# ICS/OT — OPC UA

```
event.dataset:zeek.conn AND destination.port:4840 | groupby source.ip destination.ip
```

```
event.dataset:zeek.conn AND destination.port:4840 AND NOT source.ip:<OT_RANGE> | groupby source.ip destination.ip
```

## What this does

Reviews ICS/OT communications and impact-related activity involving Opc Ua. Use the results with the surrounding host, user, time, and network context before escalating.

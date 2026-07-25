# ICS/OT — BACnet

```
event.dataset:zeek.conn AND destination.port:47808 | groupby source.ip destination.ip
```

```
event.dataset:zeek.bacnet | groupby source.ip destination.ip bacnet.service
```

## What this does

Reviews ICS/OT communications and impact-related activity involving Bacnet. Use the results with the surrounding host, user, time, and network context before escalating.

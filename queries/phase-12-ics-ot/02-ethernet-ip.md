# ICS/OT — EtherNet/IP

```
event.dataset:zeek.conn AND destination.port:(44818 OR 2222) | groupby source.ip destination.ip
```

```
event.dataset:zeek.enip | groupby source.ip destination.ip enip.command
```

## What this does

Reviews ICS/OT communications and impact-related activity involving Ethernet Ip. Use the results with the surrounding host, user, time, and network context before escalating.

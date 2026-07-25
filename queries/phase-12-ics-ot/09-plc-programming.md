# ICS/OT — PLC Programming / Logic Download

## What this does

Reviews ICS/OT communications and impact-related activity involving Plc Programming. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.s7comm AND s7comm.function:(*Download* OR *Upload*) | groupby source.ip destination.ip
```

```
event.dataset:zeek.cip AND cip.service:*Write* | groupby source.ip destination.ip
```

```
event.dataset:zeek.modbus AND modbus.function:*Write* | groupby source.ip destination.ip
```

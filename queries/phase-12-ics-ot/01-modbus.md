# ICS/OT — Modbus

```
event.dataset:zeek.modbus | groupby source.ip destination.ip modbus.function
```

```
event.dataset:zeek.conn AND destination.port:502 | groupby source.ip destination.ip
```

```
event.dataset:zeek.modbus AND modbus.function:(*Write* OR *Force*) | groupby source.ip destination.ip modbus.function
```

## What this does

Reviews ICS/OT communications and impact-related activity involving Modbus. Use the results with the surrounding host, user, time, and network context before escalating.

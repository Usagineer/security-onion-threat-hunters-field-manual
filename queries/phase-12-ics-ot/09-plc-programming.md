# ICS/OT — PLC Programming / Logic Download

```
event.dataset:zeek.s7comm AND s7comm.function:(*Download* OR *Upload*) | groupby source.ip destination.ip
```

```
event.dataset:zeek.cip AND cip.service:*Write* | groupby source.ip destination.ip
```

```
event.dataset:zeek.modbus AND modbus.function:*Write* | groupby source.ip destination.ip
```

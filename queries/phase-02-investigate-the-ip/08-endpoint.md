# Endpoint for this IP (Elastic Defend / Endgame)

```
event.module:endpoint AND host.ip:<IP>
```

```
event.module:endpoint AND event.category:network AND host.ip:<IP> | groupby process.name destination.ip destination.port
```

```
event.module:endpoint AND event.category:process AND host.ip:<IP> | groupby process.name process.parent.name
```

```
event.module:endpoint AND event.category:network AND (source.ip:<IP> OR destination.ip:<IP>)
```

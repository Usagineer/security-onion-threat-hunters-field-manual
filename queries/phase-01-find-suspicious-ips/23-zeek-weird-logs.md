# Zeek Weird Logs

```
event.dataset:zeek.weird | groupby zeek.weird.name
```

```
event.dataset:zeek.weird AND zeek.weird.name:<name> | groupby source.ip destination.ip
```

```
event.dataset:zeek.weird AND source.ip:<HOST> | groupby zeek.weird.name
```

## What this does

Finds and prioritizes suspicious network behavior associated with Zeek Weird Logs. Use the results with the surrounding host, user, time, and network context before escalating.

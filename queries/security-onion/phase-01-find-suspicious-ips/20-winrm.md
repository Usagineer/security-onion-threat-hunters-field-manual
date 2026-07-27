# WinRM (5985 / 5986)

## What this does

Finds and prioritizes suspicious network behavior associated with Winrm. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.conn AND destination.port:(5985 OR 5986) | groupby source.ip destination.ip
```

```
source.ip:<SOURCE> AND destination.port:(5985 OR 5986)
```

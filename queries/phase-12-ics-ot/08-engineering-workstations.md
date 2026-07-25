# ICS/OT — Engineering Workstations

```
event.dataset:zeek.conn AND destination.port:(102 OR 502 OR 44818 OR 20000 OR 4840) AND NOT source.ip:<EWS_RANGE> | groupby source.ip destination.ip destination.port
```

```
event.category:process AND process.name:("Step7.exe" OR "s7tia*.exe" OR "RSLogix*.exe" OR "Studio 5000*.exe" OR "TIA Portal*")
```

## What this does

Reviews ICS/OT communications and impact-related activity involving Engineering Workstations. Use the results with the surrounding host, user, time, and network context before escalating.

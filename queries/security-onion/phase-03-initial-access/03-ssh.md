# SSH — Initial Access

## What this does

Looks for signs of initial-access activity involving Ssh. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.conn AND destination.port:22 AND NOT source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8"
```

```
event.dataset:zeek.ssh AND ssh.auth.success:false | groupby source.ip destination.ip
```

```
event.dataset:zeek.ssh | groupby source.ip destination.ip ssh.auth.success
```

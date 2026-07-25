# SSH to Unexpected Hosts

```
event.dataset:zeek.conn AND destination.port:22 | groupby source.ip destination.ip connection.state
```

```
event.dataset:zeek.ssh | groupby source.ip destination.ip ssh.client ssh.auth.success
```

```
event.dataset:zeek.conn AND destination.port:22 AND NOT source.ip:"10.0.0.0/8" AND NOT source.ip:"172.16.0.0/12" AND NOT source.ip:"192.168.0.0/16" AND (destination.ip:"10.0.0.0/8" OR destination.ip:"172.16.0.0/12" OR destination.ip:"192.168.0.0/16")
```

```
event.dataset:zeek.notice AND notice.note:(*SSH* OR *Scan* OR *Password_Guessing*) | groupby source.ip destination.ip notice.note
```
## What this does

Finds and prioritizes suspicious network behavior associated with Ssh Unexpected Hosts. Use the results with the surrounding host, user, time, and network context before escalating.

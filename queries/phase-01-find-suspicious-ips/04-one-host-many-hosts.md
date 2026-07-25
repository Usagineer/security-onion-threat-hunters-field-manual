# One Host -> Many Hosts (Internal Fan-Out)

```
event.dataset:zeek.conn AND (source.ip:"10.0.0.0/8" OR source.ip:"172.16.0.0/12" OR source.ip:"192.168.0.0/16") AND (destination.ip:"10.0.0.0/8" OR destination.ip:"172.16.0.0/12" OR destination.ip:"192.168.0.0/16") | groupby source.ip destination.ip
```

```
event.dataset:zeek.conn AND source.ip:<IP> AND (destination.ip:"10.0.0.0/8" OR destination.ip:"172.16.0.0/12" OR destination.ip:"192.168.0.0/16") | groupby destination.ip destination.port network.protocol connection.state
```

```
event.dataset:zeek.conn AND source.ip:<IP> AND destination.port:(22 OR 135 OR 139 OR 389 OR 445 OR 636 OR 3268 OR 3269 OR 3389 OR 5985 OR 5986) | groupby destination.ip destination.port connection.state
```

```
event.dataset:zeek.notice AND source.ip:<IP> AND notice.note:(*Scan* OR *Address_Scan* OR *Port_Scan* OR *Password_Guessing*)
```

Many low-count destination pairs, especially with `S0`/`REJ`/reset states,
support scanning. High counts to a small fixed set of pairs support persistent
sessions or retries. Low-count touches to new LDAP/SMB/RDP/WinRM destinations
can still be targeted discovery or lateral movement.
## What this does

Finds and prioritizes suspicious network behavior associated with One Host Many Hosts. Use the results with the surrounding host, user, time, and network context before escalating.

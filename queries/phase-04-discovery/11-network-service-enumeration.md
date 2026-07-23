# Discovery — Network Service Enumeration

```
event.dataset:zeek.conn AND source.ip:<IP> AND destination.port:(135 OR 139 OR 445 OR 389 OR 636 OR 3268 OR 3269) | groupby destination.ip destination.port connection.state
```

```
event.dataset:zeek.conn AND source.ip:<IP> AND destination.port:(135 OR 139 OR 445 OR 389 OR 636 OR 3268 OR 3269) | groupby destination.ip destination.port network.protocol
```

```
event.dataset:zeek.notice AND source.ip:<IP> AND notice.note:(*Scan* OR *Address_Scan* OR *Port_Scan* OR *Enumeration*)
```

Use this after identifying a suspicious host. A small number of new LDAP/LDAPS
or SMB connections can be targeted directory or share discovery even when the
host's dominant traffic is a persistent session to only a few endpoints.
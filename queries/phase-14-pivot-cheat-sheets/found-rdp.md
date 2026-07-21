# Found RDP -> chase the logon

```
event.dataset:zeek.conn AND destination.port:3389 AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.code:4624 AND winlog.event_data.LogonType:10 | groupby source.ip winlog.event_data.TargetUserName host.name
```

```
event.code:4625 AND winlog.event_data.LogonType:10 | groupby source.ip winlog.event_data.TargetUserName
```

```
event.code:4778 | groupby winlog.event_data.AccountName source.ip
```

# Lateral Movement — SMB

```
event.dataset:zeek.conn AND destination.port:445 AND source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

```
event.dataset:zeek.smb_mapping AND smb.share:(*ADMIN$* OR *C$* OR *IPC$*) | groupby source.ip destination.ip smb.share
```

```
event.dataset:zeek.smb_files AND file.name:(*.exe OR *.dll OR *.ps1 OR *.bat) | groupby source.ip destination.ip file.name
```

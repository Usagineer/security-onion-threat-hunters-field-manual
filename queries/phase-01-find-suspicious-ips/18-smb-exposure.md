# SMB Exposure & Rare SMB

```
event.dataset:zeek.conn AND destination.port:445 | groupby source.ip destination.ip
```

```
event.dataset:zeek.smb_mapping | groupby source.ip destination.ip smb.share
```

```
event.dataset:zeek.smb_files | groupby source.ip destination.ip file.name file.path
```

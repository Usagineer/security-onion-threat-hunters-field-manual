# SMB for this IP

```
(event.dataset:zeek.smb_mapping OR event.dataset:zeek.smb_files) AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.dataset:zeek.smb_mapping AND (source.ip:<IP> OR destination.ip:<IP>) | groupby smb.share
```

```
event.dataset:zeek.smb_files AND (source.ip:<IP> OR destination.ip:<IP>) | groupby file.name file.path
```

```
event.dataset:zeek.dce_rpc AND (source.ip:<IP> OR destination.ip:<IP>) | groupby dce_rpc.endpoint dce_rpc.operation
```

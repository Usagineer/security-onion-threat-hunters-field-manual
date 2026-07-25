# SMB for this IP

## What this does

Pivots through available network, alert, and endpoint evidence for Smb. Use the results with the surrounding host, user, time, and network context before escalating.

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

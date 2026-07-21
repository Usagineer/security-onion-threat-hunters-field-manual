# Found SMB -> chase lateral movement

```
event.dataset:zeek.smb_mapping AND (source.ip:<IP> OR destination.ip:<IP>) | groupby smb.share
```

```
event.dataset:zeek.smb_files AND (source.ip:<IP> OR destination.ip:<IP>) | groupby file.name
```

```
event.code:7045 AND host.ip:<TARGET_IP>
```

```
event.code:4624 AND winlog.event_data.LogonType:3 AND host.ip:<TARGET_IP> | groupby source.ip winlog.event_data.TargetUserName
```

```
event.category:process AND process.parent.name:"wsmprovhost.exe" AND host.ip:<TARGET_IP>
```

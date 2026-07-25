# SMB Exposure & Rare SMB

## What this does

Finds and prioritizes suspicious network behavior associated with Smb Exposure. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.conn AND destination.port:(139 OR 445) | groupby source.ip destination.ip destination.port connection.state
```

```
event.dataset:zeek.smb_mapping | groupby source.ip destination.ip smb.share
```

```
event.dataset:zeek.smb_files | groupby source.ip destination.ip file.name file.path
```

```
event.dataset:zeek.conn AND source.ip:<IP> AND destination.port:(139 OR 445) | groupby destination.ip destination.port connection.state
```

Low-count SMB touches to several new peers may be more important than the
highest-count file-server traffic. Prioritize peer-to-peer SMB, failed probes,
admin shares, and executable or script writes.
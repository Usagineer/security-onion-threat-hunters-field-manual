# SMB — Initial Access

```
event.dataset:zeek.conn AND destination.port:445 AND NOT source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8"
```

```
event.module:suricata AND rule.name:(*EternalBlue* OR *MS17-010* OR *DoublePulsar*)
```

```
event.dataset:zeek.smb_mapping AND NOT source.ip:"10.0.0.0/8" | groupby source.ip destination.ip smb.share
```

## What this does

Looks for signs of initial-access activity involving Smb. Use the results with the surrounding host, user, time, and network context before escalating.

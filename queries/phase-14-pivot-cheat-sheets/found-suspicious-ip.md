# Found a suspicious IP -> run the Master IP Pivot

```
source.ip:<IP> OR destination.ip:<IP>
```

```
event.dataset:zeek.dns AND (source.ip:<IP> OR dns.answers:<IP>)
```

```
event.dataset:zeek.http AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.dataset:zeek.ssl AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
(event.dataset:zeek.smb_mapping OR event.dataset:zeek.smb_files) AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.module:suricata AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.module:endpoint AND host.ip:<IP>
```

## What this does

Provides the next investigative pivots after finding Suspicious Ip. Use the results with the surrounding host, user, time, and network context before escalating.

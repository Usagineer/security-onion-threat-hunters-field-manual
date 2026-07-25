# Master IP Pivot (run top to bottom for <IP>)

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
event.dataset:zeek.conn AND destination.port:3389 AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.dataset:zeek.conn AND destination.port:(5985 OR 5986) AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.module:suricata AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.module:endpoint AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.module:endpoint AND event.category:process AND host.ip:<IP>
```

## What this does

Finds and prioritizes suspicious network behavior associated with Master Ip Pivot. Use the results with the surrounding host, user, time, and network context before escalating.

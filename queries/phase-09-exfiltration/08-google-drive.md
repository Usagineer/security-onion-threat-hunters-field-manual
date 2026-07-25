# Exfiltration — Google Drive

## What this does

Looks for collection or exfiltration behavior involving Google Drive. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.ssl AND tls.client.server_name:(*drive.google.com OR *docs.google.com OR *googleapis.com) | groupby source.ip tls.client.server_name
```

```
event.dataset:zeek.conn AND destination.ip:<GDRIVE_IP> AND source.bytes:>50000000 | groupby source.ip
```

# Exfiltration — Mega

```
event.dataset:zeek.ssl AND tls.client.server_name:(*mega.nz OR *mega.co.nz OR *mega.io) | groupby source.ip tls.client.server_name
```

```
event.category:process AND process.name:("MEGAsync.exe" OR "megacmd.exe")
```

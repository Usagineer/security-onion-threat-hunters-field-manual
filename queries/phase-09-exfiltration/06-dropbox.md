# Exfiltration — Dropbox

```
event.dataset:zeek.ssl AND tls.client.server_name:(*dropbox* OR *dropboxusercontent*) | groupby source.ip tls.client.server_name
```

```
event.dataset:zeek.dns AND dns.question.name:*dropbox* | groupby source.ip
```

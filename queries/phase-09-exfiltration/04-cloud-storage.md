# Exfiltration — Cloud Storage (general)

## What this does

Looks for collection or exfiltration behavior involving Cloud Storage. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.ssl AND tls.client.server_name:(*mega.nz OR *mega.co.nz OR *pcloud.com OR *sync.com OR *box.com OR *wetransfer.com OR *transfer.sh OR *anonfiles* OR *gofile.io OR *file.io) | groupby source.ip tls.client.server_name
```

```
event.dataset:zeek.dns AND dns.question.name:(*mega.nz OR *wetransfer.com OR *transfer.sh OR *gofile.io OR *anonfiles*) | groupby source.ip dns.question.name
```

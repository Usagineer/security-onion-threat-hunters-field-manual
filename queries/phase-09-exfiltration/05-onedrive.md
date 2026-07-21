# Exfiltration — OneDrive

```
event.dataset:zeek.ssl AND tls.client.server_name:(*onedrive* OR *1drv* OR *sharepoint* OR *live.com) | groupby source.ip tls.client.server_name
```

```
event.dataset:zeek.conn AND destination.ip:<ONEDRIVE_IP> AND source.bytes:>50000000 | groupby source.ip
```

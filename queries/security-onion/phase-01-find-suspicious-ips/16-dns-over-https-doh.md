# DNS over HTTPS (DoH)

## What this does

Finds and prioritizes suspicious network behavior associated with Dns Over Https Doh. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.ssl AND tls.client.server_name:(*dns.google OR *cloudflare-dns.com OR *mozilla.cloudflare-dns.com OR *dns.quad9.net OR *doh.opendns.com OR *dns.nextdns.io OR *doh.cleanbrowsing.org OR *dns.adguard.com)
```

```
event.dataset:zeek.conn AND destination.port:443 AND destination.ip:("1.1.1.1" OR "1.0.0.1" OR "8.8.8.8" OR "8.8.4.4" OR "9.9.9.9")
```

```
event.dataset:zeek.ssl AND tls.client.server_name:*cloudflare-dns.com | groupby source.ip
```

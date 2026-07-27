# Cloud & VPS Providers - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **cloud vps providers** to surface anomalous network infrastructure and communication patterns. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

Falcon network telemetry and `asn()`. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

```cql
#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| asn:=asn(RemoteAddressIP4)
| asn.org=/(amazon|google|microsoft|digitalocean|linode|akamai|ovh|vultr|hetzner|choopa)/i
| groupBy([RemoteAddressIP4, asn.org, RemotePort], function=[count(as=connections), count(aid, distinct=true, as=endpoints)], limit=max)
```

## Tuning and investigation notes

- Set an explicit time range and validate the returned fields against a representative raw event.
- Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.

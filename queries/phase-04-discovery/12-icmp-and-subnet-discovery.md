# Discovery — ICMP and Subnet Enumeration

> UNVERIFIED: Validate the Zeek ICMP dataset name and tune the threshold to local monitoring tools.

```
event.dataset:zeek.conn AND network.transport:icmp AND source.ip:<HOST> | groupby destination.ip
```

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<SUSPECTED_SUBNET> | groupby destination.ip destination.port
```

```
event.dataset:zeek.notice AND source.ip:<HOST> AND notice.note:(*Scan* OR *Address_Scan* OR *Port_Scan*)
```

Corroborate a fan-out against the host role and its process telemetry. Inventory,
monitoring, and OT polling systems commonly scan; an interactive shell followed by
new reachability tests is materially more suspicious.

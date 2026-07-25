# ICS/OT — IT-to-OT Boundary and HMI Impact

> UNVERIFIED: Replace placeholders with approved engineering-workstation and OT ranges; validate protocol coverage.

```
event.dataset:zeek.conn AND source.ip:<NON_EWS_RANGE> AND destination.ip:<OT_RANGE> AND destination.port:(102 OR 502 OR 1883 OR 20000 OR 2222 OR 2404 OR 44818 OR 4840) | groupby source.ip destination.ip destination.port
```

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<OT_RANGE> | groupby destination.ip destination.port
```

```
event.category:process AND host.ip:<HMI_IP> AND process.command_line:(*docker* OR *mysqldump* OR *scp* OR *systemctl* OR *service* OR *kill *)
```

Treat an IT-to-OT connection as a lead, not proof: monitoring and engineering
tools can be expected. Raise priority when a non-engineering host reaches an OT
service, an HMI account is used from a new source, or collection/configuration
commands appear near the connection.

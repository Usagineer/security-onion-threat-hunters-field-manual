# C2 — Proxies and Reverse Tunnels

> UNVERIFIED: Validate process telemetry and tune known administrative tunnels out of the results.

```
event.category:process AND process.name:(ssh OR ssh.exe OR plink.exe) AND process.command_line:(*" -R "* OR *" -D "* OR *" -L "* OR *ProxyCommand* OR *"-N "*)
```

```
event.category:process AND process.command_line:(*socks5* OR *socks-proxy* OR *tcp-connect* OR *"socat "*)
```

```
event.dataset:zeek.conn AND source.ip:<HOST> AND NOT destination.ip:<INTERNAL_RANGES> | groupby destination.ip destination.port network.bytes event.duration
```

Pair the process command line with the network connection. An encrypted tunnel
may hide the final destination and payload, so preserve endpoint evidence and
record byte counts on both sides of the pivot.

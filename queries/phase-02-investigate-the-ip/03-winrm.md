# WinRM for this IP

```
event.dataset:zeek.conn AND destination.port:(5985 OR 5986) AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.dataset:zeek.http AND destination.port:(5985 OR 5986) AND (source.ip:<IP> OR destination.ip:<IP>)
```

```
event.category:process AND process.name:"wsmprovhost.exe" AND host.ip:<IP>
```

## What this does

Pivots through available network, alert, and endpoint evidence for Winrm. Use the results with the surrounding host, user, time, and network context before escalating.

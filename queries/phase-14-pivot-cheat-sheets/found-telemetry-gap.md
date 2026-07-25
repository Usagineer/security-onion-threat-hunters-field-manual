# Found a telemetry gap -> test for defense impairment

> UNVERIFIED: This workflow depends on which endpoint datasets your Security Onion deployment receives.

```
host.name:<HOST> AND event.category:process
```

```
host.name:<HOST> AND event.category:process AND @timestamp:[<LAST_SEEN> TO <FIRST_SEEN_AFTER_GAP>]
```

```
host.name:<HOST> AND event.category:process AND process.command_line:(*"fltmc unload"* OR *"netsh advfirewall"* OR *"sc stop"* OR *"systemctl stop"*)
```

```
event.dataset:zeek.conn AND source.ip:<HOST_IP> AND @timestamp:[<LAST_SEEN> TO <FIRST_SEEN_AFTER_GAP>]
```

Compare endpoint silence with network activity and central-agent health. A host
that keeps making connections while its process telemetry disappears should be
treated as potentially impaired, not as inactive.

## What this does

Provides the next investigative pivots after finding Telemetry Gap. Use the results with the surrounding host, user, time, and network context before escalating.

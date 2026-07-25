# Event 4769 — Kerberos Service Ticket

## What this does

Reviews Windows and Active Directory event evidence involving Kerberos Service Ticket. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4769 | groupby winlog.event_data.ServiceName winlog.event_data.TargetUserName
```

```
event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17 AND NOT winlog.event_data.ServiceName:krbtgt
```

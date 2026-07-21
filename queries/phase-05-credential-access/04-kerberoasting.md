# Credential Access — Kerberoasting

```
event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17 AND NOT winlog.event_data.ServiceName:krbtgt AND NOT winlog.event_data.ServiceName:*$
```

```
event.code:4769 | groupby winlog.event_data.ServiceName winlog.event_data.TargetUserName
```

```
event.dataset:zeek.kerberos AND kerberos.request_type:"TGS" AND kerberos.cipher:*rc4*
```

```
event.category:process AND process.command_line:(*Request-SPNTicket* OR *Rubeus* AND *kerberoast* OR *GetUserSPNs*)
```

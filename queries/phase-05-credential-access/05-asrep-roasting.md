# Credential Access — AS-REP Roasting

## What this does

Looks for credential-access behavior involving Asrep Roasting. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:4768 AND winlog.event_data.PreAuthType:0
```

```
event.code:4768 AND winlog.event_data.TicketEncryptionType:0x17 AND winlog.event_data.PreAuthType:0
```

```
event.dataset:zeek.kerberos AND kerberos.request_type:"AS" AND kerberos.success:true
```

```
event.category:process AND process.command_line:(*Rubeus* AND *asreproast* OR *Get-ASREPHash*)
```

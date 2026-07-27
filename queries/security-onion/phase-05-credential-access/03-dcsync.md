# Credential Access — DCSync

## What this does

Looks for credential-access behavior involving Dcsync. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.dce_rpc AND dce_rpc.operation:("DRSGetNCChanges" OR "drsuapi_DsGetNCChanges")
```

```
event.code:4662 AND winlog.event_data.Properties:(*1131f6aa* OR *1131f6ad* OR *89e95b76*)
```

```
event.category:process AND process.command_line:(*lsadump::dcsync* OR *dcsync /domain*)
```

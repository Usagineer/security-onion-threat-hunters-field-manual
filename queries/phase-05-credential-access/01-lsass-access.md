# Credential Access — LSASS

```
event.category:process AND process.command_line:(*comsvcs.dll*MiniDump* OR *comsvcs.dll,#24* OR *rundll32*minidump*)
```

```
event.code:(4656 OR 4663) AND winlog.event_data.ObjectName:*lsass*
```

```
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe*
```

```
event.category:process AND process.command_line:(*lsass* AND *dump*)
```

## What this does

Looks for credential-access behavior involving Lsass Access. Use the results with the surrounding host, user, time, and network context before escalating.

# Credential Access — NTDS.dit

## What this does

Looks for credential-access behavior involving Ntds Dit. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:process AND process.command_line:(*ntdsutil* OR *ntds.dit* OR *create full* OR *ifm*)
```

```
event.category:process AND process.command_line:(*vssadmin* AND *create* AND *shadow*)
```

```
event.category:process AND process.name:("ntdsutil.exe" OR "vssadmin.exe" OR "diskshadow.exe")
```

```
event.dataset:zeek.smb_files AND file.name:*ntds.dit*
```

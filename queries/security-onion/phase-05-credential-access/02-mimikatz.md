# Credential Access — Mimikatz

## What this does

Looks for credential-access behavior involving Mimikatz. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:process AND process.command_line:(*sekurlsa* OR *privilege::debug* OR *lsadump* OR *kerberos::* OR *crypto::* OR *mimikatz*)
```

```
event.category:process AND process.pe.original_file_name:"mimikatz.exe"
```

```
event.category:process AND process.command_line:(*logonpasswords* OR *pth /user* OR *ptt /ticket*)
```

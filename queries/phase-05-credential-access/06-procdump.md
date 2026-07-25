# Credential Access — Procdump

```
event.category:process AND process.name:("procdump.exe" OR "procdump64.exe")
```

```
event.category:process AND process.command_line:(*-ma* AND *lsass*)
```

```
event.category:process AND process.command_line:(*procdump* AND *lsass*)
```

## What this does

Looks for credential-access behavior involving Procdump. Use the results with the surrounding host, user, time, and network context before escalating.

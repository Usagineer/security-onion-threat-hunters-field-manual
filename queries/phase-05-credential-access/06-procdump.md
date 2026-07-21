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

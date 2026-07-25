# Persistence — Startup Folder

## What this does

Looks for persistence mechanisms involving Startup Folder. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:file AND file.path:*Start Menu*Programs*Startup*
```

```
event.category:file AND event.type:creation AND file.path:*Startup* | groupby host.name file.name process.name
```

```
event.code:11 AND winlog.event_data.TargetFilename:*Startup*
```

# Exfiltration — Archive Creation

```
event.category:process AND process.name:("7z.exe" OR "7za.exe" OR "rar.exe" OR "winrar.exe" OR "tar.exe" OR "makecab.exe")
```

```
event.category:process AND process.command_line:(*.7z OR *.rar OR *.zip OR *.tar OR *.cab) AND process.command_line:(*a * OR *-r* OR *compress*)
```

```
event.category:file AND event.type:creation AND file.extension:(zip OR rar OR 7z OR tar OR gz) | groupby host.name process.name file.name
```

## What this does

Looks for collection or exfiltration behavior involving Archive Creation. Use the results with the surrounding host, user, time, and network context before escalating.

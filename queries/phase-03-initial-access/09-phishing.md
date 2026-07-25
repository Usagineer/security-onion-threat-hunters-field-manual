# Phishing — Initial Access

```
event.dataset:zeek.http AND file.name:(*.doc* OR *.xls* OR *.zip OR *.iso OR *.htm* OR *.lnk OR *.js)
```

```
event.dataset:zeek.files AND file.mime_type:("application/x-dosexec" OR "application/zip" OR "application/x-7z-compressed") | groupby source.ip destination.ip file.name
```

```
event.category:process AND process.parent.name:("outlook.exe" OR "winword.exe" OR "excel.exe") AND process.name:("powershell.exe" OR "cmd.exe" OR "wscript.exe" OR "mshta.exe")
```

## What this does

Looks for signs of initial-access activity involving Phishing. Use the results with the surrounding host, user, time, and network context before escalating.

# Found PowerShell -> chase execution chain

```
event.category:process AND process.name:("powershell.exe" OR "pwsh.exe") AND process.command_line:(*-enc* OR *-EncodedCommand*)
```

```
event.category:process AND process.command_line:(*DownloadString* OR *DownloadFile* OR *Net.WebClient* OR *Invoke-WebRequest*)
```

```
event.category:process AND process.command_line:(*IEX* OR *Invoke-Expression* OR *FromBase64String*)
```

```
event.module:endpoint AND event.category:network AND process.name:("powershell.exe" OR "pwsh.exe") | groupby destination.ip destination.port
```

```
event.category:process AND process.parent.name:("powershell.exe" OR "pwsh.exe") | groupby process.name
```

## What this does

Provides the next investigative pivots after finding Powershell. Use the results with the surrounding host, user, time, and network context before escalating.

# Drive-by Downloads — Initial Access

```
event.module:suricata AND rule.category:("A Network Trojan was detected" OR "Exploit Kit Activity Detected")
```

```
event.dataset:zeek.files AND file.mime_type:"application/x-dosexec" | groupby source.ip destination.ip file.name
```

```
event.dataset:zeek.http AND file.mime_type:"application/x-dosexec" | groupby url.domain url.original
```

```
event.category:process AND process.parent.name:("chrome.exe" OR "msedge.exe" OR "firefox.exe" OR "iexplore.exe") AND process.name:("powershell.exe" OR "cmd.exe" OR "wscript.exe" OR "cscript.exe" OR "mshta.exe")
```

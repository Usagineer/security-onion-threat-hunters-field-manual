# C2 — User Agents

```
event.dataset:zeek.http | groupby user_agent.original
```

```
event.dataset:zeek.http AND user_agent.original:(*powershell* OR *python* OR *curl* OR *wget* OR *Go-http* OR *WinHttp* OR *Nim* OR *libwww*)
```

```
event.dataset:zeek.http AND (NOT user_agent.original:* OR user_agent.original:"") | groupby source.ip destination.ip
```

# C2 — User Agents

## What this does

Looks for command-and-control behavior involving User Agents. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:zeek.http | groupby user_agent.original
```

```
event.dataset:zeek.http AND user_agent.original:(*powershell* OR *python* OR *curl* OR *wget* OR *Go-http* OR *WinHttp* OR *Nim* OR *libwww*)
```

```
event.dataset:zeek.http AND (NOT user_agent.original:* OR user_agent.original:"") | groupby source.ip destination.ip
```

# Web Attacks — Initial Access

```
event.module:suricata AND rule.category:("Web Application Attack" OR "Attempted Administrator Privilege Gain") | groupby rule.name source.ip destination.ip
```

```
event.dataset:zeek.http AND url.original:(*union*select* OR *cmd.exe* OR *etc*passwd* OR *WEB-INF*)
```

```
event.dataset:zeek.http AND http.response.status_code:500 | groupby source.ip url.original
```

```
event.dataset:zeek.http AND http.request.method:POST AND destination.ip:"10.0.0.0/8" | groupby source.ip url.original
```

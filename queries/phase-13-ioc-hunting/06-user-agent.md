# IOC — User-Agent

```
user_agent.original:"*<ioc_user_agent>*"
```

```
event.dataset:zeek.http AND user_agent.original:"*<ioc_user_agent>*" | groupby source.ip destination.ip
```

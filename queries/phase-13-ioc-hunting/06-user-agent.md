# IOC — User-Agent

## What this does

Searches Security Onion telemetry for the specified indicator type: User Agent. Use the results with the surrounding host, user, time, and network context before escalating.

```
user_agent.original:"*<ioc_user_agent>*"
```

```
event.dataset:zeek.http AND user_agent.original:"*<ioc_user_agent>*" | groupby source.ip destination.ip
```

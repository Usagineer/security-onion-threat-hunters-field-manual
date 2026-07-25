# Persistence — COM Hijacking

## What this does

Looks for persistence mechanisms involving Com Hijacking. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:registry AND registry.path:*CLSID*InprocServer32*
```

```
event.category:registry AND registry.path:*Classes*CLSID*LocalServer32*
```

```
event.code:13 AND winlog.event_data.TargetObject:*InprocServer32*
```

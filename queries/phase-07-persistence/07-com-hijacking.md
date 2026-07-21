# Persistence — COM Hijacking

```
event.category:registry AND registry.path:*CLSID*InprocServer32*
```

```
event.category:registry AND registry.path:*Classes*CLSID*LocalServer32*
```

```
event.code:13 AND winlog.event_data.TargetObject:*InprocServer32*
```

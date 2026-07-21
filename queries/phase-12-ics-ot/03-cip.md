# ICS/OT — CIP

```
event.dataset:zeek.cip | groupby source.ip destination.ip cip.service
```

```
event.dataset:zeek.cip AND cip.service:(*Write* OR *Forward_Open* OR *Set_Attribute*) | groupby source.ip destination.ip
```

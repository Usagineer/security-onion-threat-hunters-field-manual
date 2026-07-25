# ICS/OT — CIP

```
event.dataset:zeek.cip | groupby source.ip destination.ip cip.service
```

```
event.dataset:zeek.cip AND cip.service:(*Write* OR *Forward_Open* OR *Set_Attribute*) | groupby source.ip destination.ip
```

## What this does

Reviews ICS/OT communications and impact-related activity involving Cip. Use the results with the surrounding host, user, time, and network context before escalating.

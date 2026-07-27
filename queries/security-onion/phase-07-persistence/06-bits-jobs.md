# Persistence — BITS Jobs

## What this does

Looks for persistence mechanisms involving Bits Jobs. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:process AND process.name:"bitsadmin.exe" AND process.command_line:(*/transfer* OR */create* OR */addfile* OR */setnotifycmdline*)
```

```
event.category:process AND process.command_line:(*Start-BitsTransfer* OR *Import-Module BitsTransfer*)
```

```
event.code:(59 OR 60 OR 3) AND winlog.channel:*Bits-Client*
```

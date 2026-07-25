# Found repeated PowerShell -> scope propagation

## What this does

Provides the next investigative pivots after finding Repeated Powershell. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:process AND process.name:("powershell.exe" OR "pwsh.exe") | groupby process.command_line host.name user.name
```

```
event.category:process AND process.name:("powershell.exe" OR "pwsh.exe") AND process.command_line:(*\\\\*\\sysvol\\* OR *\\\\*\\netlogon\\*) | groupby host.name user.name process.parent.name process.command_line
```

```
event.category:process AND process.name:("powershell.exe" OR "pwsh.exe") AND process.parent.name:"svchost.exe" | groupby host.name user.name process.command_line
```

```
event.code:4698 | groupby host.name winlog.event_data.TaskName winlog.event_data.SubjectUserName
```

Use a repeated command line as the campaign key: determine how many hosts ran
it, under which accounts, and whether it came from a domain share or Task
Scheduler. Validate approved software and deployment tooling before concluding
that repeated execution is malicious.
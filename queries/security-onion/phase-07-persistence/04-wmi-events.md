# Persistence — WMI Event Subscriptions

## What this does

Looks for persistence mechanisms involving Wmi Events. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.code:(5859 OR 5861)
```

```
event.category:process AND process.command_line:(*__EventFilter* OR *CommandLineEventConsumer* OR *ActiveScriptEventConsumer* OR *__EventConsumer*)
```

```
event.category:process AND process.name:"wmic.exe" AND process.command_line:(*ActiveScriptEventConsumer* OR *__EventFilter*)
```

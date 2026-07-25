# Credential Access — SAM

## What this does

Looks for credential-access behavior involving Sam. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.category:process AND process.command_line:(*reg* AND *save* AND *sam*)
```

```
event.category:process AND process.command_line:(*reg* AND *save* AND *system*)
```

```
event.category:process AND process.command_line:(*esentutl* OR *shadowcopy* AND *sam*)
```

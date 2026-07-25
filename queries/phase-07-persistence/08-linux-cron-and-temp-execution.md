# Persistence — Linux Cron and Temporary-Path Execution

> UNVERIFIED: Requires Linux process and file telemetry. Validate path field mappings before use.

```
event.category:process AND process.parent.name:(cron OR crond) AND process.command_line:(*/tmp/* OR */var/tmp/* OR */dev/shm/*)
```

```
event.category:process AND process.name:(crontab OR cron OR crond) AND process.command_line:(*-e* OR *"/etc/cron"* OR *"/var/spool/cron"*)
```

```
event.category:file AND file.path:(*/etc/cron.*/* OR */var/spool/cron/* OR */var/spool/cron/crontabs/*)
```

For a suspected cron entry, capture its full command, owner, parent process,
first-seen time, and outbound network activity. Remove the persistence mechanism
before killing its child process, or it may restart on the next schedule.

## What this does

Looks for persistence mechanisms involving Linux Cron And Temp Execution. Use the results with the surrounding host, user, time, and network context before escalating.

# IOC — YARA (via Strelka file scanning)

## What this does

Searches Security Onion telemetry for the specified indicator type: Yara. Use the results with the surrounding host, user, time, and network context before escalating.

```
event.dataset:strelka AND strelka.scan.yara.matches:*
```

```
event.dataset:strelka AND strelka.scan.yara.matches:"<rule_name>" | groupby file.name source.ip destination.ip
```

```
event.dataset:strelka | groupby strelka.scan.yara.matches
```

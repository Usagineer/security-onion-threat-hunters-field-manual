# IOC — File Hash

```
event.dataset:zeek.files AND (file.hash.sha256:"<sha256>" OR file.hash.md5:"<md5>" OR file.hash.sha1:"<sha1>")
```

```
event.dataset:strelka AND (file.hash.sha256:"<sha256>" OR file.hash.md5:"<md5>")
```

```
event.module:endpoint AND (process.hash.sha256:"<sha256>" OR file.hash.sha256:"<sha256>")
```

## What this does

Searches Security Onion telemetry for the specified indicator type: Hash. Use the results with the surrounding host, user, time, and network context before escalating.

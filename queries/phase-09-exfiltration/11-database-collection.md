# Exfiltration — Database Collection and Staging

> UNVERIFIED: Validate container and database process names used in your environment.

```
event.category:process AND process.name:(mysqldump OR pg_dump OR sqlcmd.exe OR mongoexport OR expdp) | groupby host.name user.name process.name process.command_line
```

```
event.category:process AND process.command_line:(*"docker exec"* AND *(mysqldump OR pg_dump OR mongoexport)*)
```

```
event.category:process AND process.name:(scp OR scp.exe OR sftp OR sftp.exe OR rsync) AND process.command_line:*
```

Database export is often legitimate. Escalate when it is unusual for the account,
comes from an interactive or newly remote-logged-on session, writes to a temporary
location, or is followed by an external transfer.

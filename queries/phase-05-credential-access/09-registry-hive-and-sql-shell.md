# Credential Access — Registry Hives and SQL Server Shells

> UNVERIFIED: Validate command-line collection and SQL Server process names in your deployment.

```
event.category:process AND process.parent.name:"sqlservr.exe" AND process.name:(cmd.exe OR powershell.exe OR reg.exe)
```

```
event.category:process AND process.command_line:(*"reg save"* OR *"HKLM\\SAM"* OR *"HKLM\\SYSTEM"* OR *"HKLM\\SECURITY"*)
```

```
event.category:process AND process.command_line:(*xp_cmdshell* OR *"sp_configure"* AND *xp_cmdshell*)
```

Treat a SYSTEM hive save together with a SAM hive save as a credential-dumping
chain. Pivot from the originating process to its user, parent, created files, and
subsequent remote logons; do not rely on a registry command alone.

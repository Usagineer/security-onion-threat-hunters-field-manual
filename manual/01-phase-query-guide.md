# Phase Query Guide for New Analysts

This guide explains what each query phase is for and how to use the phases as one investigation workflow. It complements the short **What this does** section at the top of every query file.

## Before you search

1. Set an absolute time range for the alert or incident. Record the timezone.
2. Write down the initial lead: IP, host, account, domain, hash, alert, or process.
3. Replace every placeholder such as `<IP>`, `<HOST>`, `<ACCOUNT>`, and `<OT_RANGE>` before running a query.
4. Run one query at a time. Preserve its result count, time range, and useful values for the next pivot.
5. Treat every result as a lead. Confirm it with at least one independent source of context.

Use the host's role, normal administrative patterns, process ancestry, user activity, network history, and known monitoring tools to distinguish suspicious behavior from expected behavior.

## The phase workflow

```text
Alert or lead
  -> Phase 1: find anomalous network behavior
  -> Phase 2: build the IP-centered evidence picture
  -> Phases 3-13: follow the observed attacker behavior
  -> Phase 14: take the next focused pivot
  -> scope affected assets, preserve evidence, contain, eradicate, document
```

You will often move backward as new evidence appears. For example, a Phase 8 tunnel finding can lead back to Phase 6 to scope lateral movement, then forward to Phase 9 to assess transfer activity.

## Phase 1 — Find Suspicious IPs

**Purpose:** Turn broad network telemetry into a short list of investigation leads.

These queries identify rare or new destinations, internal fan-out, port scans, high-volume transfers, long-lived sessions, beaconing, unusual remote access, suspicious DNS, TLS anomalies, and IDS alerts. Use this phase when you have an alert but do not yet know which IP, host, or connection deserves attention.

**A useful result looks like:** A host contacting an uncommon external destination, probing many internal systems, repeatedly connecting at a regular interval, or making an outbound transfer inconsistent with its role.

**Next move:** Copy the IP and open Phase 2. Then use the protocol or behavior-specific phase indicated by the result.

## Phase 2 — Investigate the Suspicious IP

**Purpose:** Build a complete timeline around one IP.

The Master IP Pivot and its supporting files search connection, DNS, HTTP, TLS, SMB, RDP, WinRM, Suricata, and endpoint evidence. This phase connects a network lead to hosts, processes, domains, files, accounts, and alerts.

**A useful result looks like:** The same IP appears in DNS, TLS, endpoint network events, or an IDS alert, revealing who communicated, which process initiated it, and what happened before and after.

**Next move:** Branch into the behavior shown: web access goes to Phase 3, discovery to Phase 4, remote services to Phase 6, C2-like traffic to Phase 8, and so on.

## Phase 3 — Initial Access

**Purpose:** Determine how the actor first entered.

These queries cover RDP, VPN, SSH, web attacks and web shells, SMB, MSSQL, FTP, email, phishing, and drive-by downloads. They are most effective when correlated with the first suspicious user, host, or external IP in the incident timeline.

**A useful result looks like:** A successful remote login from an unusual source, web-server child-shell activity, a malicious attachment execution chain, or an externally sourced remote-service session.

**Next move:** Scope the account and source in Phase 6, then investigate discovery and execution on the affected host with Phases 4 and 10.

## Phase 4 — Discovery

**Purpose:** Find how an actor learned about the host, users, network, and services.

The queries look for commands such as `whoami`, `ipconfig`, `arp`, `route`, `systeminfo`, `net user`, `nltest`, `netstat`, `tasklist`, and session enumeration, plus ICMP and network service discovery.

**A useful result looks like:** Multiple reconnaissance commands close together, a shell performing host and domain discovery, or a host probing a new subnet or directory service.

**Next move:** Use the discovered targets, accounts, and services in Phase 5 or Phase 6.

## Phase 5 — Credential Access

**Purpose:** Detect attempts to obtain passwords, hashes, tickets, or reusable secrets.

This phase covers LSASS and ProcDump activity, Mimikatz, DCSync, Kerberoasting, AS-REP roasting, SAM/SYSTEM registry hives, NTDS.dit, and SQL Server shell behavior.

**A useful result looks like:** A process accessing LSASS, a SAM and SYSTEM hive save occurring together, unusual Kerberos ticket requests, or directory replication from a non-domain-controller context.

**Next move:** Preserve evidence, identify the account or credential at risk, and use Phase 6 plus Phase 11 to scope where it was used.

## Phase 6 — Lateral Movement

**Purpose:** Find the spread from one host to another.

Queries cover SMB, PsExec, WMI, WinRM, RDP, remote services, scheduled tasks, DCOM, and valid-account spread. Use them with a known source host, account, or time window.

**A useful result looks like:** New remote logons, administrative share access, service creation, remote process execution, or one account reaching multiple hosts over remote-management protocols.

**Next move:** For each affected host, inspect execution and persistence with Phases 7 and 10, and use Phase 11 to reconstruct authentication.

## Phase 7 — Persistence

**Purpose:** Find mechanisms intended to survive reboot, logoff, or cleanup.

This phase covers registry run keys, startup folders, services, WMI subscriptions, scheduled tasks, BITS jobs, COM hijacking, and Linux cron jobs with temporary-path execution.

**A useful result looks like:** A new task, service, autorun registry value, cron entry, or executable launched from a temporary directory by a scheduler.

**Next move:** Preserve the artifact and its configuration first. Determine the parent process, file hash, outbound connections, and first-seen time before eradication.

## Phase 8 — Command and Control

**Purpose:** Detect how a compromised host communicates with an operator or remote infrastructure.

The queries look for beaconing, DNS tunneling, long-lived connections, JA3 fingerprints, rare domains, suspicious user agents, HTTP POST activity, TLS anomalies, SOCKS proxies, and reverse tunnels.

**A useful result looks like:** Regularly timed connections, rare domain use, encrypted sessions with unusual TLS metadata, or SSH commands that establish forwarding.

**Next move:** Scope every host using the same infrastructure in Phase 1 or Phase 13. Preserve endpoint evidence because encrypted tunnels may hide payload contents.

## Phase 9 — Exfiltration

**Purpose:** Find collection, staging, and movement of data outside the environment.

This phase covers FTP, SFTP, SCP, cloud storage, large uploads, archive creation, and database exports or containerized database dumps.

**A useful result looks like:** An unusual database dump, archive creation followed by outbound transfer, a new external SCP destination, or high outbound bytes from a sensitive host.

**Next move:** Determine data owner and scope, preserve transfer metadata and endpoint evidence, then use Phase 8 to investigate the transport infrastructure.

## Phase 10 — Malware and Execution

**Purpose:** Detect suspicious process execution and attempts to weaken security controls.

The queries cover Office child processes, LOLBins, Certutil, BITSAdmin, MSHTA, Rundll32, Regsvr32, encoded PowerShell, download cradles, Invoke-Expression, defense impairment, and process masquerading.

**A useful result looks like:** An Office process starting PowerShell, a system-looking process outside its expected path, a security-control unload command, or a binary executing from a temporary path.

**Next move:** Pivot to the process parent, command line, hash, signer, files, and network connections. If telemetry suddenly stops, use the Phase 14 telemetry-gap pivot.

## Phase 11 — Active Directory and Windows Events

**Purpose:** Reconstruct authentication, privileges, account changes, execution, and service changes from Windows events.

The files focus on common high-value event IDs, including successful and failed logons, special privileges, process creation, scheduled tasks, account/group changes, Kerberos tickets, and service installation.

**A useful result looks like:** Failed logons followed by success, a privileged logon from a new source, unexpected group membership changes, or a new service installed near remote activity.

**Next move:** Pivot by account, source IP, destination host, and logon type; correlate with Phase 6 network and endpoint evidence.

## Phase 12 — ICS / OT

**Purpose:** Safely investigate industrial protocol traffic and possible impact on OT systems.

Queries cover Modbus, EtherNet/IP, CIP, DNP3, BACnet, OPC UA, S7, engineering workstations, PLC programming, unauthorized controllers, and IT-to-OT/HMI activity.

**A useful result looks like:** A non-engineering host reaching an OT protocol, an unfamiliar controller, programming/write activity, or an HMI showing unusual collection or service-control commands.

**Next move:** Validate the host's role with OT owners before assuming malicious activity. Prioritize preservation and operational safety; do not disrupt control traffic without the appropriate authority.

## Phase 13 — IOC Hunting

**Purpose:** Scope known indicators across all available telemetry.

Searches are provided for IPs, domains, URLs, hashes, JA3/JA3S, user agents, YARA matches, and Sigma detections. This phase is useful after an external report, malware analysis, or a confirmed finding supplies an indicator.

**A useful result looks like:** The same indicator on more than one host, a domain resolving before a suspicious connection, or a file hash linked to an executing process.

**Next move:** Use Phase 2 for each affected IP or host, then scope the related behavior in the appropriate tactic phase.

## Phase 14 — Pivot Cheat Sheets

**Purpose:** Answer “what should I search next?” without rereading the full manual.

These short workflows start from a finding such as beaconing, DNS, PowerShell, RDP, SMB, WinRM, a suspicious IP, repeated PowerShell, or a telemetry gap.

**A useful result looks like:** A rapid chain from the first observation to corroborating evidence, affected hosts, accounts, processes, and network destinations.

**Next move:** Return to the associated tactic phase for deeper scoping and document the decision, evidence, and conclusion.

## Good analyst habits

- Keep an investigation timeline with timestamps and timezone.
- Record both positive findings and ruled-out benign explanations.
- Do not rely only on `host.name` in cloned or dual-homed environments; include agent identity and IP context.
- Compare suspicious artifacts with clean peers before remediation.
- Preserve process, file, and memory evidence before deleting persistence or killing malware.
- Treat lost endpoint telemetry as an investigative lead, not proof that the host is inactive.

> Use these queries only for authorized defensive operations. Validate every result against your environment before containment or eradication.

# Security Onion Threat Hunter's Field Manual

A workflow-first library of hunting queries for **Security Onion 2.x**. It uses Security Onion's Elastic data, Zeek, Suricata, and endpoint telemetry to help analysts move from an initial lead to evidence-backed scoping.

This is a living Markdown manual. The query files are the source of truth and are designed to stay open beside the Security Onion SOC Hunt interface during an investigation.

## Start here

1. Set an **absolute incident time range** before searching. Confirm the timezone and widen only when needed.
2. Start in [Phase 1](queries/phase-01-find-suspicious-ips/) if you have a lead but no clear host or destination; otherwise use [Phase 2](queries/phase-02-investigate-the-ip/) for a known IP.
3. Replace placeholders such as `<IP>`, `<HOST>`, `<ACCOUNT>`, and `<OT_RANGE>` with your case values or approved ranges.
4. Run one query at a time, preserve the time window, and pivot on host, user, process, IP, domain, and alert context.
5. Use the phase matching the behavior you find; Phase 14 provides short next-step pivots for common findings.

Do not treat one result as proof of compromise. Corroborate it with host role, user activity, process ancestry, network behavior, historical baseline, and other available telemetry.

## Query format

Every query file starts with a **What this does** section, followed by bare copy/paste query blocks. Some newer hunts are marked **UNVERIFIED**: validate their fields, telemetry prerequisites, and thresholds in your Security Onion deployment before operational use.

The examples use ECS-style fields as exposed by Security Onion. Field availability and exact names can vary with sensor configuration, Elastic Agent integrations, and Security Onion version.

## Investigation workflow

```text
Lead or alert
  -> Phase 1: identify suspicious network behavior
  -> Phase 2: pivot through all available evidence for the IP
  -> Phases 3-13: investigate the observed behavior
  -> Phase 14: use a focused next-step pivot
  -> scope, preserve evidence, contain, eradicate, and document
```

When endpoint telemetry stops unexpectedly, do not assume the host is quiet. Compare the gap with network activity and central-agent health; a host that continues communicating while endpoint data disappears may have impaired defenses.

## Query library

| Phase | Use it for |
|---|---|
| 1. Find Suspicious IPs | Rare, new, anomalous, scanning, beaconing, or high-volume network behavior. |
| 2. Investigate the IP | Network, DNS, HTTP, TLS, Suricata, SMB, RDP, WinRM, and endpoint pivots for a known IP. |
| 3. Initial Access | RDP, VPN, SSH, web, SMB, SQL, FTP, email, phishing, and web-shell/RCE leads. |
| 4. Discovery | Account, host, network, service, session, and subnet discovery. |
| 5. Credential Access | LSASS, Mimikatz, DCSync, Kerberos abuse, registry hives, NTDS, and SQL-shell behavior. |
| 6. Lateral Movement | SMB, PsExec, WMI, WinRM, RDP, DCOM, remote services, tasks, and valid-account spread. |
| 7. Persistence | Registry, startup folders, services, WMI, tasks, BITS, COM, and Linux cron persistence. |
| 8. Command and Control | Beacons, DNS tunnels, TLS, rare domains, HTTP, user agents, proxies, and reverse tunnels. |
| 9. Exfiltration | FTP/SFTP/SCP, cloud storage, large uploads, archives, and database collection. |
| 10. Malware / Execution | Suspicious child processes, LOLBins, script execution, defense impairment, and masquerading. |
| 11. Active Directory | High-value Windows and AD event IDs for authentication, privilege, process, account, and service changes. |
| 12. ICS / OT | Industrial protocols, engineering workstations, PLC programming, unauthorized controllers, and IT-to-OT activity. |
| 13. IOC Hunting | IP, domain, URL, hash, JA3, user-agent, YARA, and Sigma searches. |
| 14. Pivot Cheat Sheets | Immediate follow-up queries after finding beaconing, DNS, PowerShell, RDP, SMB, WinRM, an IP, or a telemetry gap. |

## Repository layout

```text
.
├── README.md
├── CONTRIBUTING.md
├── queries/                 # 14 workflow phases; one Markdown file per hunt
├── manual/                  # long-form Phase 1 manual and front matter
├── templates/               # hunt authoring template
└── automation/              # optional query-runner tooling
```

## Contributing

- Keep queries focused and place one copy/paste query per bare code block.
- Add a short **What this does** explanation before the queries.
- Use placeholders instead of incident-specific IPs, accounts, malware names, domains, or application names.
- State telemetry prerequisites and mark proposed queries **UNVERIFIED** until tested.
- Include normal-versus-suspicious context and useful next pivots where practical.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete standards.

## Safety and limitations

Use this material only for authorized defensive security operations, threat hunting, and education. Tune every query to your environment and validate findings before containment or eradication. Network-only telemetry cannot recover encrypted tunnel contents or host-only artifacts; preserve endpoint and memory evidence when available.

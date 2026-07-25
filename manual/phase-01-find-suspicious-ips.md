# Phase 1 — Find Suspicious IPs

> **Start here when you have nothing.** These hunts answer one question:
>
> ## *"Which IP should I investigate?"*
>
> Every hunt in this phase ends by handing you an IP address. The moment you have one, you go to the **Master IP Pivot** (end of this phase, and the whole of Phase 2) and run it to ground.

---

## Phase 1 contents

| # | Hunt | Category | Conf. | Diff. |
|---|------|----------|:---:|:---:|
| 1 | Rare Destination IP | Rare IPs | 🟡 | 🟢 |
| 2 | Rare Source IP | Rare IPs | 🟡 | 🟢 |
| 3 | New / First-Seen External IP | Rare IPs | 🟡 | 🟡 |
| 4 | One Host → Many Hosts (internal fan-out) | Connection Volume | 🔴 | 🟡 |
| 5 | Many Hosts → One Destination (C2 convergence) | Connection Volume | 🟡 | 🟢 |
| 6 | One Host → Many Ports (port scan) | Connection Volume | 🔴 | 🟢 |
| 7 | Large Outbound Transfer (exfil) | Connection Volume | 🟡 | 🟢 |
| 8 | Large Inbound Transfer (staging/download) | Connection Volume | 🟢 | 🟢 |
| 9 | Long-Lived Connections | Connection Volume | 🟡 | 🟢 |
| 10 | Beaconing (regular interval) | Connection Volume | 🔴 | 🔴 |
| 11 | Servers / IoT Talking Directly to the Internet | External Comms | 🟡 | 🟢 |
| 12 | Connections to Rare Countries | External Comms | 🟡 | 🟢 |
| 13 | Cloud & VPS Providers | External Comms | 🟡 | 🟡 |
| 14 | TOR | External Comms | 🔴 | 🟡 |
| 15 | Dynamic DNS | External Comms | 🟡 | 🟢 |
| 16 | DNS over HTTPS (DoH) | External Comms | 🟡 | 🟡 |
| 17 | Rogue / External DNS Servers | External Comms | 🟡 | 🟢 |
| 18 | SMB Exposure & Rare SMB | Protocol | 🟡 | 🟢 |
| 19 | RDP Reach & Exposure | Protocol | 🟡 | 🟢 |
| 20 | WinRM (5985/5986) | Protocol | 🔴 | 🟡 |
| 21 | SSH to Unexpected Hosts | Protocol | 🟡 | 🟢 |
| 22 | Suricata Alert Triage | IDS Correlation | 🟡 | 🟢 |
| 23 | Zeek Weird Logs | IDS Correlation | 🟡 | 🟡 |
| 24 | JA3 / JA3S & TLS Anomalies | IDS Correlation | 🟡 | 🔴 |
| 25 | IOC Sweep (IP / Domain / URL / Hash / JA3 / UA) | IOC Hunting | 🔴 | 🟢 |

---

## Security Onion field quick reference

The fields you will use constantly in Phase 1. All are ECS as surfaced in the SOC **Hunt** UI.

### Core connection (`event.dataset:zeek.conn`)

| Field | What it is |
|---|---|
| `source.ip` / `destination.ip` | The two endpoints |
| `source.port` / `destination.port` | Ports |
| `network.transport` | `tcp` / `udp` / `icmp` |
| `network.protocol` | App protocol Zeek identified (`dns`, `http`, `ssl`, `smb`, `ssh`, …) |
| `connection.state` | Zeek `conn_state` (`SF`, `S0`, `REJ`, `RSTO`, …) |
| `source.bytes` / `destination.bytes` | Payload bytes each direction |
| `network.bytes` | Total bytes |
| `event.duration` | Connection duration (**nanoseconds** in ECS) |
| `network.community_id` | Hash that ties the same flow across Zeek **and** Suricata — your best cross-log pivot |

### Enrichment (added by Security Onion)

| Field | What it is |
|---|---|
| `destination.geo.country_name` / `destination.geo.country_iso_code` | GeoIP country |
| `destination.as.organization.name` | Owning org / ISP (ASN name) |
| `destination.as.number` | ASN |

### Protocol logs

| Dataset | Key fields |
|---|---|
| `zeek.dns` | `dns.question.name`, `dns.question.type_name`, `dns.answers` |
| `zeek.http` | `http.request.method`, `url.domain`, `url.original`, `user_agent.original`, `http.response.status_code` |
| `zeek.ssl` | `tls.client.server_name` (SNI), `tls.client.ja3`, `tls.server.ja3s`, `tls.version` |
| `zeek.smb_mapping` / `zeek.smb_files` | `smb.share`, `file.path` |
| `zeek.ssh` | `ssh.client`, `ssh.server`, `ssh.auth.success` |
| `zeek.kerberos` | `kerberos.client`, `kerberos.service` |
| `zeek.notice` | `notice.note`, `notice.msg` |
| `zeek.weird` | `zeek.weird.name` |
| Suricata | `event.module:suricata`, `rule.name`, `rule.category`, `event.severity` |

### The one trick that makes Hunt fast

Security Onion's **Hunt** interface supports a pipe grouping syntax. Instead of eyeballing thousands of rows, aggregate them:

```
event.dataset:zeek.conn | groupby destination.ip
```

You can group by multiple fields:

```
event.dataset:zeek.conn | groupby source.ip destination.ip destination.port
```

- **To find rare things**, sort the grouped table **ascending** by count — the rows at the bottom (count 1, 2, 3) are your leads.
- **To find noisy things** (scans, fan-out), sort **descending**.

CIDR works on IP fields, so you can carve out your own space:

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" AND NOT destination.ip:"172.16.0.0/12" AND NOT destination.ip:"192.168.0.0/16"
```

> Throughout Phase 1, replace the RFC1918 ranges above with **your** internal ranges. A saved search with your ranges baked in is worth building on day one.

---

## Investigation methodology (the loop you repeat)

```
1. Aggregate        (| groupby)  →  find the outlier
2. Isolate          (source.ip:<IP> OR destination.ip:<IP>)
3. Characterize     (what protocol? how much data? how often? how long?)
4. Pivot            (DNS → HTTP → TLS → SMB/RDP → Suricata → Endpoint)
5. Decide           (benign / needs more / escalate)
```

Every hunt below is step 1. The **Master IP Pivot** at the end is steps 2–4. Phase 2 expands that pivot into a full playbook.

---

## Hunt 1 — Rare Destination IP

| | |
|---|---|
| **ATT&CK** | `T1071` (Application Layer Protocol) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~2 min |

### Why Hunt This

Attackers communicate with destinations that almost nobody else in your environment talks to. Popular destinations (Windows Update, Office 365, Google) are contacted by hundreds of hosts. C2 is usually contacted by one.

**Step 1 — Aggregate external destinations**

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" AND NOT destination.ip:"172.16.0.0/12" AND NOT destination.ip:"192.168.0.0/16" | groupby destination.ip
```

**Step 2 — Sort ascending**

Sort the grouped table by count **ascending**. The destinations at the bottom (contacted by only 1–2 internal hosts) are your candidates.

**Step 3 — Add context to the rare ones**

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby source.ip destination.port destination.as.organization.name
```

**Step 4 — Isolate the candidate (hand-off to the pivot)**

```
source.ip:<IP> OR destination.ip:<IP>
```

**Look for**

- ✔ A single internal host talking to a rare external IP repeatedly
- ✔ Rare IP owned by a VPS/hosting ASN (not a known CDN/SaaS)
- ✔ Long connections, large uploads, or regular intervals to that IP
- ✔ A matching Suricata alert or Zeek notice on the same `network.community_id`


### Attack Use

Attackers often place C2 or staging on a destination that only one compromised host contacts.

### Attacker Pivot

By this point, the attacker may have learned that one host communicates with low-prevalence infrastructure. From **Rare Destination IP**, the likely next move is to retain the rare destination as C2 or staging while testing additional protocols. For the investigation, pivot from the rare IP to DNS, TLS, HTTP, and the endpoint process, then search for other hosts using the same infrastructure.

**Next Pivots**

- Confirmed rare + external? → **Master IP Pivot** (below)
- Rare IP is a hosting/VPS ASN? → Hunt 13 (Cloud & VPS)
- Regular timing? → Hunt 10 (Beaconing)
- Big uploads? → Hunt 7 (Large Outbound)

**Analyst Notes**

- *Normal:* Windows Update, Chrome/Edge telemetry, Office 365 / Azure, Google, Apple, corporate SaaS, NTP pools, CDN edge nodes.
- *Suspicious:* Unknown VPS (DigitalOcean/Vultr/Hetzner droplets), residential ISP space, a cloud VM with no business reason, freshly registered infrastructure.

**Investigation Checklist**

- [ ] Save the rare IP as an IOC
- [ ] Note the ASN / country
- [ ] Pivot to DNS (what name resolved to it?)
- [ ] Pivot to Suricata on the community_id
- [ ] Export PCAP if the box is worth escalating

---

## Hunt 2 — Rare Source IP

| | |
|---|---|
| **ATT&CK** | `T1071`, `T1021` (Remote Services) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~2 min |

### Why Hunt This

Hunt 1 finds rare *destinations*. This finds rare *initiators* — an internal host that suddenly starts originating connections it never used to (a normally quiet server reaching out, a printer speaking SMB to a DC, a workstation initiating admin protocols).

**Step 1 — Aggregate internal originators**

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" | groupby source.ip
```

(Swap in your internal range.)

**Step 2 — Sort ascending, then profile the quiet ones**

For a low-volume source that looks off:

```
event.dataset:zeek.conn AND source.ip:<IP> | groupby destination.ip destination.port network.protocol
```

**Step 3 — Isolate**

```
source.ip:<IP> OR destination.ip:<IP>
```

**Look for**

- ✔ A server or appliance originating outbound internet connections (they usually *receive*)
- ✔ A workstation originating admin protocols (SMB/RDP/WinRM/LDAP) to many peers
- ✔ A host whose destination/port profile changed abruptly


### Attack Use

A compromised quiet host may begin initiating connections for C2, scanning, or remote administration.

### Attacker Pivot

By this point, the attacker may have learned which normally quiet internal host can originate traffic. From **Rare Source IP**, the likely next move is to use that host to scan, administer peers, or reach external infrastructure. For the investigation, pivot to the new destinations, process owner, account, and any change in the host role.

**Next Pivots**

- Originating admin protocols? → Hunt 4 (One → Many) and Phase 6 (Lateral Movement)
- Originating to internet? → Hunt 11 (Servers talking to internet)
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Patch/backup servers, vuln scanners, monitoring hosts, jump boxes.
- *Suspicious:* A "quiet" host that abruptly starts initiating; role reversal (server → client to the internet).

**Investigation Checklist**

- [ ] Identify the host's expected role (asset inventory)
- [ ] Compare against its historical baseline
- [ ] Pivot to Endpoint for the initiating process
- [ ] Escalate if role is violated

---

## Hunt 3 — New / First-Seen External IP

| | |
|---|---|
| **ATT&CK** | `T1071`, `T1583` (Acquire Infrastructure) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟡 Intermediate |
| **Hunt Time** | ~5 min |

### Why Hunt This

Freshly stood-up attacker infrastructure has no history in your data. A destination that appears for the first time today — especially one a single host talks to — is a classic lead.

**Step 1 — Baseline window (e.g. last 7–30 days, excluding today)**

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.ip
```

Export or note this set as your "known" destinations.

**Step 2 — Today's destinations**

Re-run the same query with the time picker set to **today only**, then compare: IPs present today but absent from the baseline are "first-seen."

**Step 3 — Profile each first-seen IP**

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby source.ip destination.port destination.as.organization.name
```

**Look for**

- ✔ First-seen IP contacted by exactly one internal host
- ✔ First-seen IP on a hosting/VPS ASN
- ✔ First-seen domain (Hunt 15) resolving to it


### Attack Use

Attackers can bring up fresh infrastructure to avoid reputation and historical detections.

### Attacker Pivot

By this point, the attacker may have learned that newly deployed infrastructure is not yet blocked or baselined. From **New / First-Seen External IP**, the likely next move is to move delivery or C2 to the first-seen address before reputation catches up. For the investigation, pivot from the first-seen address to its resolving domains, ASN, TLS identity, connection timing, and other hosts that contacted it.

**Next Pivots**

- → Hunt 1 (Rare Destination) to confirm rarity
- → Hunt 15 (Dynamic DNS) / Hunt 25 (IOC Sweep) on the resolving domain
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* New CDN edges, new SaaS vendors, cloud auto-scaling IPs rotate constantly — expect churn.
- *Suspicious:* First-seen + single host + hosting ASN + long/beaconing connection is a strong stack of weak signals.

**Investigation Checklist**

- [ ] Confirm the IP is genuinely new (check longer window)
- [ ] WHOIS / passive DNS the IP (offline OSINT)
- [ ] Save as IOC
- [ ] Pivot to TLS/HTTP for the SNI / Host header

---

## Hunt 4 — One Host → Many Hosts (Internal Fan-Out)

| | |
|---|---|
| **ATT&CK** | `T1046` (Network Service Discovery), `T1021` (Remote Services) |
| **Confidence** | 🔴 High |
| **Difficulty** | 🟡 Intermediate |
| **Hunt Time** | ~5 min |

### Why Hunt This

One internal host connecting to an unusually large number of *other internal* hosts is the signature of scanning, spraying, or lateral movement. This is one of the highest-value hunts in Phase 1.

**Step 1 — Count internal peers per source**

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8" | groupby source.ip
```

Sort **descending**. A host touching dozens/hundreds of internal peers stands out.

**Step 2 — What is it doing to them?**

```
event.dataset:zeek.conn AND source.ip:<IP> AND destination.ip:"10.0.0.0/8" | groupby destination.port network.protocol
```

**Step 3 — Which peers, and did the connections succeed?**

```
event.dataset:zeek.conn AND source.ip:<IP> AND destination.ip:"10.0.0.0/8" | groupby destination.ip connection.state
```

`S0`/`REJ` at scale = scanning; `SF` at scale on 445/3389/5985 = likely lateral movement.

**Look for**

- ✔ One source → many internal destinations
- ✔ Concentrated on 445 (SMB), 3389 (RDP), 5985/5986 (WinRM), 135 (RPC), 389/636 (LDAP)
- ✔ Successful (`SF`) admin-protocol connections fanning out


### Attack Use

An attacker may fan out to locate reachable hosts, validate stolen credentials, or deploy tools through remote services.

### Attacker Pivot

By this point, the attacker may have learned which internal hosts answer and which remote protocols are reachable. From **One Host → Many Hosts (Internal Fan-Out)**, the likely next move is to select responsive targets for exploitation, credential use, or lateral movement. For the investigation, pivot from the source host to protocol-specific evidence, target logons, and destination-side execution.

**Next Pivots**

- SMB fan-out? → Hunt 18, then Phase 6 (PsExec / service creation)
- RDP fan-out? → Hunt 19, Phase 6
- WinRM fan-out? → Hunt 20 (🔴)
- → **Master IP Pivot** on the source

**Analyst Notes**

- *Normal:* Vulnerability scanners, SCCM/patch servers, monitoring, backup — **know your scanners** and allowlist them.
- *Suspicious:* A workstation (not a server) fanning out on admin ports; fan-out from a host that never did it before.

**Investigation Checklist**

- [ ] Confirm the source is not a sanctioned scanner
- [ ] Map the destination set (subnet? DCs? all workstations?)
- [ ] Pivot to Endpoint on the source for the scanning/lateral process
- [ ] Escalate — this is usually worth it

---

## Hunt 5 — Many Hosts → One Destination (C2 Convergence)

| | |
|---|---|
| **ATT&CK** | `T1071`, `T1102` (Web Service) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

The inverse of Hunt 4. When many internal hosts all talk to one external IP that isn't a known service, that IP may be a shared C2, a malicious ad/redirect, or a watering hole.

**Step 1 — Count internal talkers per external destination**

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" | groupby destination.ip
```

Sort **descending**, then ignore the obvious CDNs/SaaS and look for the odd high-fan-in IP.

**Step 2 — Who is the destination?**

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby destination.as.organization.name destination.geo.country_name destination.port
```

**Step 3 — What name did they use to reach it?**

```
event.dataset:zeek.dns AND dns.answers:<IP>
```

**Look for**

- ✔ Many hosts → one hosting/VPS IP
- ✔ Convergence on an odd port (not 80/443)
- ✔ All hosts resolved the same freshly-registered / DGA-looking domain


### Attack Use

A shared C2 server, watering hole, or malicious redirect can draw multiple internal hosts to one destination.

### Attacker Pivot

By this point, the attacker may have learned that several victims can reach one shared destination. From **Many Hosts → One Destination (C2 Convergence)**, the likely next move is to operate common C2, redirect, or watering-hole infrastructure across the affected set. For the investigation, pivot to the common domain, process, timing, and affected-host set to distinguish a shared service from an attack.

**Next Pivots**

- → Hunt 10 (Beaconing) — shared C2 often beacons
- → Hunt 25 (IOC Sweep) on the domain/IP
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* CDNs, SaaS, telemetry endpoints, update servers — huge legitimate fan-in.
- *Suspicious:* High fan-in to a hosting ASN on a non-standard port, or to a domain nobody can explain.

**Investigation Checklist**

- [ ] Rule out known SaaS/CDN
- [ ] Save IP + domain as IOCs
- [ ] Check whether all talkers share a patient-zero / common software
- [ ] Escalate if it looks like shared C2

---

## Hunt 6 — One Host → Many Ports (Port Scan)

| | |
|---|---|
| **ATT&CK** | `T1046` (Network Service Discovery) |
| **Confidence** | 🔴 High |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

A single source hitting many distinct destination ports (on one or many targets) is port scanning / service discovery — reconnaissance that precedes lateral movement.

**Step 1 — Distinct ports per source**

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" | groupby source.ip destination.port
```

Group and look for sources spanning a wide, sequential-looking port range.

**Step 2 — Confirm scan behavior (failed connections)**

```
event.dataset:zeek.conn AND source.ip:<IP> AND connection.state:("S0" OR "REJ" OR "RSTO")
```

Lots of `S0` (no reply) / `REJ` = scanning.

**Step 3 — Check Zeek's own scan notice**

```
event.dataset:zeek.notice AND source.ip:<IP>
```

(Look for `Scan::Port_Scan` / `Scan::Address_Scan` in `notice.note`.)

**Look for**

- ✔ One source touching many ports with mostly failed states
- ✔ Zeek `Scan::` notices
- ✔ Scan immediately followed by a successful connection on one port (they found something)


### Attack Use

An attacker may scan ports to identify a usable service before exploiting it or moving laterally.

### Attacker Pivot

By this point, the attacker may have learned which ports and services are exposed on selected targets. From **One Host → Many Ports (Port Scan)**, the likely next move is to choose a vulnerable service or a protocol that accepts stolen credentials. For the investigation, pivot from the scanner to discovered targets and follow any successful connection on SMB, RDP, WinRM, SSH, or another exposed service.

**Next Pivots**

- Found an open service they connected to? → the relevant protocol hunt (18–21)
- → Hunt 4 (fan-out) if scanning many hosts too
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Nessus/Qualys/OpenVAS scanners, Nmap from IT — allowlist sanctioned scanners.
- *Suspicious:* Scanning from a workstation, or from a server toward DCs/workstations.

**Investigation Checklist**

- [ ] Confirm not a sanctioned scan
- [ ] Identify what (if anything) answered
- [ ] Pivot to Endpoint for the scanning tool
- [ ] Escalate

---

## Hunt 7 — Large Outbound Transfer (Exfil)

| | |
|---|---|
| **ATT&CK** | `T1041` (Exfil over C2), `T1567` (Exfil to Web Service), `T1030` |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~5 min |

### Why Hunt This

Exfiltration shows up as an internal host *sending* far more than it receives, or a single large upload to an external destination.

**Step 1 — Rank outbound flows by bytes sent**

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" AND source.bytes:>10000000 | groupby source.ip destination.ip
```

(Adjust the `source.bytes` threshold to your environment — start ~10 MB.)

**Step 2 — Confirm the direction ratio**

Open a candidate flow and compare `source.bytes` (uploaded) vs `destination.bytes` (downloaded). Exfil = `source.bytes` ≫ `destination.bytes`.

**Step 3 — Where did it go?**

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<DEST> | groupby destination.as.organization.name destination.port network.protocol
```

**Look for**

- ✔ Upload ≫ download to an external IP
- ✔ Destination = file-sharing / cloud storage (Hunt targets: Dropbox, Mega, Google Drive, pastebin, transfer.sh)
- ✔ Upload over an odd protocol/port, or bursts on a beacon schedule


### Attack Use

An attacker may upload collected files, archives, or database exports to an external destination.

### Attacker Pivot

By this point, the attacker may have learned which egress destination and transfer size leave the network successfully. From **Large Outbound Transfer (Exfil)**, the likely next move is to increase exfiltration, split it into chunks, or change to a backup channel. For the investigation, pivot backward to archive creation and collection, then forward to the destination, account, repeat transfers, and C2 channel.

**Next Pivots**

- Cloud storage destination? → Phase 9 (Exfiltration)
- Regular bursts? → Hunt 10 (Beaconing)
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Backups to cloud, legit large uploads (video, dev artifacts), OneDrive/GDrive sync.
- *Suspicious:* Large upload from a host with no reason to; upload to personal/anonymous file services; archive-then-upload pattern.

**Investigation Checklist**

- [ ] Quantify volume and destination
- [ ] Pivot to Endpoint for archive creation (`.zip`/`.rar`/`.7z`) preceding the upload
- [ ] Save destination as IOC
- [ ] Escalate — potential data loss

---

## Hunt 8 — Large Inbound Transfer (Staging / Download)

| | |
|---|---|
| **ATT&CK** | `T1105` (Ingress Tool Transfer) |
| **Confidence** | 🟢 Low |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

Attackers pull tooling and second-stage payloads onto a beachhead. A host downloading a large blob from a rare external IP — especially over plain HTTP — can be tool ingress.

**Step 1 — Rank inbound flows by bytes received**

```
event.dataset:zeek.conn AND destination.ip:"10.0.0.0/8" AND NOT source.ip:"10.0.0.0/8" AND destination.bytes:>10000000 | groupby destination.ip source.ip
```

**Step 2 — What was downloaded (files / MIME)?**

```
event.dataset:zeek.files AND destination.ip:<INTERNAL_HOST>
```

Look at `file.mime_type` and any `file.name` — executables, scripts, archives from odd sources are the leads.

**Step 3 — Over what?**

```
event.dataset:zeek.http AND destination.ip:<EXTERNAL_IP> AND source.ip:<INTERNAL_HOST>
```

**Look for**

- ✔ Large download from a rare/hosting IP
- ✔ Executable/script/archive MIME type
- ✔ Plain-HTTP download of a binary (no TLS) from a non-CDN


### Attack Use

An attacker may download tools or a second-stage payload after gaining a foothold.

### Attacker Pivot

By this point, the attacker may have learned which host can retrieve large content and where it can be delivered. From **Large Inbound Transfer (Staging / Download)**, the likely next move is to execute the downloaded payload and use the host as a beachhead. For the investigation, pivot to the endpoint process, downloaded file, parent process, execution, persistence, and the hosting infrastructure.

**Next Pivots**

- Executable downloaded? → Phase 10 (Malware) + Endpoint
- Downloaded by a LOLBin (certutil/bitsadmin)? → Phase 10
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Software updates, installer downloads, OS images, container pulls — high legit volume.
- *Suspicious:* Binary over plain HTTP from a VPS; download landing in a temp/user-writable path (confirm on endpoint).

**Investigation Checklist**

- [ ] Capture the file hash (`zeek.files`)
- [ ] Sweep the hash (Hunt 25)
- [ ] Pivot to Endpoint for what wrote/executed it
- [ ] Escalate if unsigned/unknown executable

---

## Hunt 9 — Long-Lived Connections

| | |
|---|---|
| **ATT&CK** | `T1071`, `T1571` (Non-Standard Port) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

Interactive C2, reverse shells, and tunnels hold a single connection open for a long time. A multi-hour flow to an external IP is worth a look — legitimate long connections are a short, known list.

**Step 1 — Rank by duration**

`event.duration` is in **nanoseconds** in ECS. One hour ≈ `3.6e12` ns.

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" AND event.duration:>3600000000000 | groupby source.ip destination.ip destination.port
```

**Step 2 — Profile the destination**

```
event.dataset:zeek.conn AND destination.ip:<IP> | groupby destination.as.organization.name network.protocol
```

**Look for**

- ✔ Hours-long TCP flow to a hosting/VPS IP
- ✔ Long connection on a non-standard port
- ✔ Long connection carrying little data (keep-alive C2) *or* steady transfer (tunnel)


### Attack Use

An attacker may keep a tunnel, reverse shell, or interactive remote session open for long periods.

### Attacker Pivot

By this point, the attacker may have learned which destination permits a durable session and which path stays open. From **Long-Lived Connections**, the likely next move is to carry an interactive shell, tunnel, or long-running C2 channel over it. For the investigation, pivot to the responsible process, port owner, byte pattern, destination, and related beaconing.

**Next Pivots**

- Steady low-data heartbeat? → Hunt 10 (Beaconing)
- Non-standard port? → Master IP Pivot + Endpoint for the process/port owner
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* VPNs, SSH sessions, RDP, database connections, message queues, websocket/streaming, monitoring agents.
- *Suspicious:* Long flow to a VPS with no matching business app; long flow on a random high port.

**Investigation Checklist**

- [ ] Note duration, port, byte ratio
- [ ] Identify the destination org
- [ ] Pivot to Endpoint for the owning process
- [ ] Escalate if it maps to no known app

---

## Hunt 10 — Beaconing (Regular Interval)

| | |
|---|---|
| **ATT&CK** | `T1071`, `T1573` (Encrypted Channel) |
| **Confidence** | 🔴 High |
| **Difficulty** | 🔴 Advanced |
| **Hunt Time** | ~15 min |

### Why Hunt This

C2 implants "phone home" on a schedule (every 30s, 60s, 5m — often with jitter). Regular, low-variance timing between a host and a destination is one of the strongest network indicators of an implant.

**Step 1 — Find candidate pairs (many connections, small, to one dest)**

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

High connection **count** to a single external IP with small per-connection bytes = beacon candidate. Note the pair.

**Step 2 — Pull the raw timeline for the pair**

```
event.dataset:zeek.conn AND source.ip:<HOST> AND destination.ip:<DEST>
```

Sort by `@timestamp` ascending and eyeball the inter-arrival gaps. Near-constant spacing (allowing for jitter) = beaconing.

**Step 3 — Corroborate with the connection log's own signal**

Look for consistent small `network.bytes`, consistent `destination.port`, and a matching Suricata alert on the `network.community_id`.

**Look for**

- ✔ Near-constant interval between connections (± jitter)
- ✔ Uniform small payloads
- ✔ Destination on a hosting/VPS ASN
- ✔ Persisting across hours/days regardless of user activity


### Attack Use

A beacon lets an implant receive tasks and maintain contact with an operator.

### Attacker Pivot

By this point, the attacker may have learned which hosts are infected and how often they can reach C2. From **Beaconing (Regular Interval)**, the likely next move is to send tasks, alter sleep intervals, or migrate to secondary infrastructure. For the investigation, pivot to the destination infrastructure, TLS or HTTP identity, endpoint process, other hosts with the same pattern, and possible transfer activity.

**Next Pivots**

- Beacon confirmed? → Phase 8 (Command & Control) — full beacon analysis
- TLS beacon? → Hunt 24 (JA3) to fingerprint the client
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* NTP, monitoring/heartbeat agents, software update checks, DNS keep-alives, telemetry — **all** beacon. Baseline them.
- *Suspicious:* Beacon to a hosting IP with no agent installed there; encrypted beacon with a rare JA3; beacon that survives reboot but maps to no service.

**Investigation Checklist**

- [ ] Measure the interval and jitter
- [ ] Rule out known agents/telemetry
- [ ] Fingerprint JA3 (if TLS)
- [ ] Pivot to Endpoint for the beaconing process
- [ ] Escalate — high confidence when benign agents are excluded

---

## Hunt 11 — Servers / IoT Talking Directly to the Internet

| | |
|---|---|
| **ATT&CK** | `T1071`, `T1190` (Exploit Public-Facing App — as a consequence) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

Devices that should *never* originate arbitrary internet traffic — domain controllers, database servers, printers, cameras, PLCs — doing so is either misconfiguration or compromise. Both deserve attention.

**Step 1 — Outbound internet by internal originators**

```
event.dataset:zeek.conn AND source.ip:"10.0.0.0/8" AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.port
```

**Step 2 — Filter to hosts that shouldn't be there**

Cross-reference the source list against asset inventory. Focus on server/appliance/OT subnets originating outbound.

**Step 3 — Isolate the offender**

```
source.ip:<SERVER_IP> AND NOT destination.ip:"10.0.0.0/8"
```

**Look for**

- ✔ A DC/DB/print server/camera making outbound internet connections
- ✔ Outbound on odd ports from infrastructure
- ✔ OT/ICS devices reaching the internet at all (see Phase 12)


### Attack Use

A compromised server, IoT device, or OT asset may initiate internet traffic to reach C2 or download tools despite policy.

### Attacker Pivot

By this point, the attacker may have learned which restricted server or device has direct egress. From **Servers / IoT Talking Directly to the Internet**, the likely next move is to use the unexpected path for C2, tool retrieval, or movement across network zones. For the investigation, pivot to asset ownership, allowed egress paths, process or firmware context, and the external destination.

**Next Pivots**

- DC reaching internet? → Phase 5 (Credential Access) + Master IP Pivot
- OT device? → Phase 12 (ICS/OT)
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Server OS/AV updates (often via proxy), NTP, licensing check-ins.
- *Suspicious:* Any direct outbound from a device policy says should be internal-only.

**Investigation Checklist**

- [ ] Confirm the device role and expected egress policy
- [ ] Identify the destination
- [ ] Pivot to Endpoint if an agent exists
- [ ] Escalate on policy violation

---

## Hunt 12 — Connections to Rare Countries

| | |
|---|---|
| **ATT&CK** | `T1071` |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

Geography is a weak-but-cheap signal. Traffic to countries where you have no business presence narrows the field fast — especially combined with a rare destination or hosting ASN.

**Step 1 — Group by destination country**

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.geo.country_name
```

Sort ascending — the rare countries are the leads.

**Step 2 — Drill into a rare country**

```
event.dataset:zeek.conn AND destination.geo.country_name:"<Country>" | groupby destination.ip source.ip destination.as.organization.name
```

**Look for**

- ✔ Traffic to a country with no business nexus
- ✔ Single host → rare-country hosting IP
- ✔ Rare country + rare destination + long/beaconing = stacked signals


### Attack Use

Attackers may host infrastructure in regions outside normal business operations or route traffic through foreign services.

### Attacker Pivot

By this point, the attacker may have learned which foreign-hosted paths are reachable without immediate blocking. From **Connections to Rare Countries**, the likely next move is to continue through that region or provider while blending with legitimate global traffic. For the investigation, pivot to the IP, ASN, domain, process, and timing; geography is supporting context, not proof.

**Next Pivots**

- → Hunt 1 (Rare Destination) to confirm
- → Hunt 13 (Cloud & VPS) if hosting ASN
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* CDNs geolocate oddly; multinational SaaS; researchers/dev teams pulling foreign repos; VPN egress. Geo alone proves nothing.
- *Suspicious:* Sustained traffic to a sanctioned/no-nexus country from a specific host, especially to hosting space.

**Investigation Checklist**

- [ ] Confirm no business reason
- [ ] Check the ASN (CDN vs hosting)
- [ ] Correlate with rarity/timing
- [ ] Escalate only with corroboration (geo is not enough alone)

---

## Hunt 13 — Cloud & VPS Providers

| | |
|---|---|
| **ATT&CK** | `T1583.003` (Virtual Private Server), `T1071` |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟡 Intermediate |
| **Hunt Time** | ~5 min |

### Why Hunt This

Adversaries rent cheap VPS instances for C2 and staging. Outbound traffic to raw VPS/hosting ASNs (as opposed to the SaaS *products* those clouds also host) is disproportionately interesting.

**Step 1 — Group by destination ASN org**

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.as.organization.name
```

**Step 2 — Focus on hosting/VPS orgs**

Look for names like DigitalOcean, Vultr, Linode/Akamai, Hetzner, OVH, Contabo, Choopa, M247, Shinjiru, etc. Then drill:

```
event.dataset:zeek.conn AND destination.as.organization.name:*DigitalOcean* | groupby destination.ip source.ip destination.port
```

(Repeat per provider of interest, or build a saved filter listing your hosting-ASN watchlist.)

**Look for**

- ✔ A single host talking to a raw VPS IP (not a recognizable SaaS)
- ✔ VPS destination on a non-standard port
- ✔ VPS + beaconing / long connection / rare-first-seen


### Attack Use

Attackers commonly rent VPS instances for disposable C2, redirectors, phishing, and staging.

### Attacker Pivot

By this point, the attacker may have learned which cloud or VPS networks are allowed and look ordinary. From **Cloud & VPS Providers**, the likely next move is to operate disposable redirectors, C2, phishing, or staging from rented infrastructure. For the investigation, pivot to the exact VM address, TLS identity, connection regularity, endpoint process, and any infrastructure reuse.

**Next Pivots**

- → Hunt 10 (Beaconing), Hunt 9 (Long connections)
- → Hunt 24 (JA3) for the TLS fingerprint
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Tons of legitimate SaaS/apps run on these clouds. The signal is *raw VM* traffic with no product identity, not "AWS/GCP/Azure exists."
- *Suspicious:* Direct-to-droplet traffic, especially self-signed TLS or odd ports.

**Investigation Checklist**

- [ ] Distinguish SaaS product vs raw VM
- [ ] Check TLS cert / SNI (Hunt 24)
- [ ] Save IP as IOC
- [ ] Escalate with corroborating signal

---

## Hunt 14 — TOR

| | |
|---|---|
| **ATT&CK** | `T1090.003` (Multi-hop Proxy: TOR) |
| **Confidence** | 🔴 High |
| **Difficulty** | 🟡 Intermediate |
| **Hunt Time** | ~5 min |

### Why Hunt This

TOR usage in most enterprises is anomalous and is used for anonymized C2, exfil, and evasion. Security Onion (Zeek) frequently flags TOR via SSL notices and known-node intel.

**Step 1 — Zeek/Suricata TOR signals**

```
event.dataset:zeek.notice AND notice.note:*Tor*
```

```
event.module:suricata AND rule.name:*TOR*
```

**Step 2 — Heuristic: TOR-style TLS on 9001/9030/443 with random-looking SNIs**

```
event.dataset:zeek.ssl AND destination.port:(9001 OR 9030 OR 9050 OR 9051)
```

**Step 3 — Isolate the internal host**

```
source.ip:<INTERNAL_HOST> AND (event.dataset:zeek.ssl OR event.dataset:zeek.conn)
```

**Look for**

- ✔ Zeek notice / Suricata sig referencing TOR
- ✔ TLS to known TOR nodes (intel match)
- ✔ Randomized/rotating self-signed-style TLS SNIs typical of TOR


### Attack Use

Attackers may use Tor to hide C2, remote access, or exfiltration paths.

### Attacker Pivot

By this point, the attacker may have learned that Tor connections can leave the environment and conceal destination identity. From **TOR**, the likely next move is to route C2 or exfiltration through the anonymity network. For the investigation, pivot to the internal host, Tor process or browser, destination role, transferred data, and related persistence or command activity.

**Next Pivots**

- → Phase 8 (C2), Phase 9 (Exfil)
- → **Master IP Pivot** on the internal host
- → Endpoint: is the Tor Browser / a bundled tor.exe present?

**Analyst Notes**

- *Normal:* Rare. Some privacy tooling, some researchers — should be sanctioned and known.
- *Suspicious:* Essentially all unsanctioned TOR. Treat as high confidence and investigate the host, not just the connection.

**Investigation Checklist**

- [ ] Confirm TOR (intel + fingerprint)
- [ ] Identify the host and user
- [ ] Pivot to Endpoint for the tor process/bundle
- [ ] Escalate

---

## Hunt 15 — Dynamic DNS

| | |
|---|---|
| **ATT&CK** | `T1568` (Dynamic Resolution) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

Cheap/free dynamic-DNS domains (`*.duckdns.org`, `*.no-ip.com`, `*.ddns.net`, `*.hopto.org`, etc.) let attackers point a memorable name at rotating infrastructure. Common in commodity RAT C2.

**Step 1 — Query DNS for dynamic-DNS providers**

```
event.dataset:zeek.dns AND dns.question.name:(*duckdns.org OR *no-ip.com OR *ddns.net OR *hopto.org OR *sytes.net OR *zapto.org OR *myftp.org OR *serveo.net OR *ngrok.io)
```

**Step 2 — Who queried, and what did it resolve to?**

```
event.dataset:zeek.dns AND dns.question.name:*duckdns.org | groupby source.ip dns.question.name dns.answers
```

**Step 3 — Isolate the client and the resolved IP**

```
source.ip:<HOST> OR destination.ip:<RESOLVED_IP>
```

**Look for**

- ✔ Internal host resolving a DDNS name
- ✔ DDNS name resolving to a hosting/VPS IP
- ✔ DDNS + beaconing / long connection to the resolved IP


### Attack Use

Attackers may use dynamic DNS to move infrastructure while retaining a stable name.

### Attacker Pivot

By this point, the attacker may have learned that a stable domain can point to changing attacker-controlled addresses. From **Dynamic DNS**, the likely next move is to rotate backend infrastructure without reconfiguring the implant or lure. For the investigation, pivot to the domain, resolved IP history, TLS/HTTP activity, endpoint process, and any other hosts resolving the name.

**Next Pivots**

- → Hunt 10 (Beaconing) on the resolved IP
- → Hunt 25 (IOC Sweep) on the domain
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Home labs, some legit remote-access setups, ngrok used by developers (should be sanctioned).
- *Suspicious:* DDNS in an enterprise with no dev/lab justification — strongly associated with commodity RAT C2.

**Investigation Checklist**

- [ ] Save the domain + resolved IP as IOCs
- [ ] Check first-seen (Hunt 3)
- [ ] Pivot to the connection to the resolved IP
- [ ] Escalate with corroboration

---

## Hunt 16 — DNS over HTTPS (DoH)

| | |
|---|---|
| **ATT&CK** | `T1071.004` (DNS), `T1572` (Protocol Tunneling) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟡 Intermediate |
| **Hunt Time** | ~5 min |

### Why Hunt This

DoH hides DNS resolution inside HTTPS, blinding your DNS monitoring. Malware and evasive tooling use it to resolve C2 without touching your resolvers. Hunt the *known DoH endpoints*.

**Step 1 — TLS SNI to known DoH providers**

```
event.dataset:zeek.ssl AND tls.client.server_name:(*dns.google OR *cloudflare-dns.com OR *mozilla.cloudflare-dns.com OR *dns.quad9.net OR *doh.opendns.com OR *dns.nextdns.io OR *doh.cleanbrowsing.org OR *dns.adguard.com)
```

**Step 2 — Direct connections to DoH resolver IPs (e.g. 1.1.1.1, 8.8.8.8 on 443)**

```
event.dataset:zeek.conn AND destination.port:443 AND destination.ip:("1.1.1.1" OR "1.0.0.1" OR "8.8.8.8" OR "8.8.4.4" OR "9.9.9.9")
```

**Step 3 — Who is doing it, and is it bypassing your resolvers?**

```
event.dataset:zeek.ssl AND tls.client.server_name:*cloudflare-dns.com | groupby source.ip
```

**Look for**

- ✔ A host reaching a DoH endpoint while *not* using your internal DNS
- ✔ DoH from a server or unusual host
- ✔ Browser DoH is common — server/appliance DoH is not


### Attack Use

Attackers may use DoH to bypass local DNS visibility or carry C2-related resolution inside encrypted web traffic.

### Attacker Pivot

By this point, the attacker may have learned which encrypted DNS provider is reachable outside normal resolver visibility. From **DNS over HTTPS (DoH)**, the likely next move is to resolve or signal infrastructure while hiding queries inside HTTPS. For the investigation, pivot to the DoH client process, destination, allowed policy, and adjacent suspicious traffic.

**Next Pivots**

- → Master IP Pivot on the host
- → Endpoint: which process is doing DoH? (browser vs. unknown)
- → Phase 8 (C2) if paired with beaconing

**Analyst Notes**

- *Normal:* Modern browsers (Firefox/Chrome/Edge) enable DoH by default for end users.
- *Suspicious:* DoH from non-browser processes, servers, or hosts that should use internal DNS only. Consider a policy to block/redirect DoH.

**Investigation Checklist**

- [ ] Determine if org policy allows DoH
- [ ] Identify the process on endpoint
- [ ] Correlate with C2 signals
- [ ] Escalate if non-browser / policy violation

---

## Hunt 17 — Rogue / External DNS Servers

| | |
|---|---|
| **ATT&CK** | `T1071.004` (DNS), `T1572` |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

In a managed network, clients should resolve only through approved internal DNS servers. A host sending DNS (udp/53, tcp/53) directly to an external resolver is bypassing controls — sometimes for tunneling or evasion.

**Step 1 — DNS to anything that isn't your resolvers**

```
event.dataset:zeek.dns AND NOT destination.ip:("<DNS1>" OR "<DNS2>") AND NOT destination.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

(Replace `<DNS1>`/`<DNS2>` with your sanctioned resolvers.)

**Step 2 — Look at what they're resolving externally**

```
event.dataset:zeek.dns AND source.ip:<HOST> AND destination.ip:<EXTERNAL_RESOLVER> | groupby dns.question.name
```

**Step 3 — Volume check (possible DNS tunneling)**

A single host generating a very high volume of unique, long, random-looking subdomains to one resolver may be tunneling.

**Look for**

- ✔ Host using an external resolver directly
- ✔ Huge count of unique subdomains under one parent domain (tunneling)
- ✔ Long TXT/NULL query patterns


### Attack Use

Attackers may point a host at an external resolver to bypass internal DNS controls or resolve malicious infrastructure.

### Attacker Pivot

By this point, the attacker may have learned that a host can bypass approved resolvers. From **Rogue / External DNS Servers**, the likely next move is to resolve malicious names directly and evade internal DNS filtering or logging. For the investigation, pivot to the client, resolver, queried names, configuration changes, and other hosts using the resolver.

**Next Pivots**

- Tunneling pattern? → Phase 8 (DNS Tunneling)
- → **Master IP Pivot**
- → Endpoint for the process making external DNS

**Analyst Notes**

- *Normal:* Misconfigured devices, some appliances with hardcoded 8.8.8.8, split-horizon setups.
- *Suspicious:* High-entropy subdomain floods, external DNS from a host that has a working internal resolver.

**Investigation Checklist**

- [ ] Confirm sanctioned resolver list
- [ ] Measure unique-subdomain volume
- [ ] Save the parent domain as IOC
- [ ] Escalate on tunneling indicators

---

## Hunt 18 — SMB Exposure & Rare SMB

| | |
|---|---|
| **ATT&CK** | `T1021.002` (SMB/Admin Shares), `T1570` (Lateral Tool Transfer) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~5 min |

### Why Hunt This

SMB (445) is the workhorse of Windows lateral movement: admin-share access, PsExec, file drops. Client-to-client SMB and access to `ADMIN$`/`C$` are the patterns to surface.

**Step 1 — All SMB flows, grouped by pair**

```
event.dataset:zeek.conn AND destination.port:445 | groupby source.ip destination.ip
```

**Step 2 — Which shares were touched?**

```
event.dataset:zeek.smb_mapping | groupby source.ip destination.ip smb.share
```

Watch for `ADMIN$`, `C$`, `IPC$` between non-admin hosts.

**Step 3 — What files moved over SMB?**

```
event.dataset:zeek.smb_files | groupby source.ip destination.ip file.name file.path
```

**Look for**

- ✔ Workstation → workstation SMB (peers usually don't need it)
- ✔ Access to `ADMIN$` / `C$` outside of admin/patch workflows
- ✔ Executables/scripts written over SMB (`.exe`, `.dll`, `.ps1`, `.bat`)


### Attack Use

Attackers may abuse exposed or unusual SMB access to enumerate shares, copy tools, or move laterally.

### Attacker Pivot

By this point, the attacker may have learned which shares, files, and administrative paths are accessible over SMB. From **SMB Exposure & Rare SMB**, the likely next move is to copy tooling, collect files, create remote execution artifacts, or move laterally. For the investigation, pivot to share access, file operations, authentication, service creation, and source-to-target relationships.

**Next Pivots**

- Admin-share write + service start? → Phase 6 (PsExec / Service Creation)
- Fan-out on 445? → Hunt 4
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Clients → file servers, SYSVOL/NETLOGON to DCs (Group Policy), patch/deployment servers writing to `ADMIN$`.
- *Suspicious:* Peer-to-peer SMB, admin-share writes of executables, SMB from a host that never used it.

**Investigation Checklist**

- [ ] Map the share and file activity
- [ ] Correlate with 4624/7045 on endpoint (Phase 11)
- [ ] Save any transferred file's hash
- [ ] Escalate on admin-share tool drop

---

## Hunt 19 — RDP Reach & Exposure

| | |
|---|---|
| **ATT&CK** | `T1021.001` (Remote Desktop Protocol) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

RDP (3389) is a top lateral-movement and initial-access vector. Surface who can reach RDP, RDP exposed to the internet, and one-to-many RDP.

**Step 1 — All RDP flows**

```
event.dataset:zeek.conn AND destination.port:3389 | groupby source.ip destination.ip
```

**Step 2 — Internet-exposed RDP (inbound from outside)**

```
event.dataset:zeek.conn AND destination.port:3389 AND NOT source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8"
```

**Step 3 — One source → many RDP targets**

```
event.dataset:zeek.conn AND destination.port:3389 AND source.ip:"10.0.0.0/8" | groupby source.ip destination.ip
```

(Sort so a single source with many distinct targets stands out.)

**Look for**

- ✔ Inbound RDP from the internet (should almost never exist)
- ✔ One host RDP-ing to many internal hosts
- ✔ RDP from a workstation acting as a jump point


### Attack Use

Attackers may use RDP with stolen credentials or exposed services to obtain interactive access.

### Attacker Pivot

By this point, the attacker may have learned which hosts expose RDP and which identities can establish sessions. From **RDP Reach & Exposure**, the likely next move is to gain interactive control, run discovery, and establish persistence. For the investigation, pivot to logon type, source IP, account, session timing, destination processes, and follow-on discovery or persistence.

**Next Pivots**

- Internet-exposed? → Phase 3 (Initial Access)
- Internal fan-out? → Phase 6 (Lateral Movement) + 4624/4625 (Phase 11)
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Admins/jump hosts → servers, VDI, sanctioned remote support.
- *Suspicious:* Internet → internal RDP, workstation → many hosts, RDP outside change windows.

**Investigation Checklist**

- [ ] Confirm exposure vs policy
- [ ] Correlate with logon events (4624 type 10) on endpoint
- [ ] Check for brute-force (many 4625 → one 4624)
- [ ] Escalate on internet exposure or fan-out

---

## Hunt 20 — WinRM (5985 / 5986)

| | |
|---|---|
| **ATT&CK** | `T1021.006` (Windows Remote Management) |
| **Confidence** | 🔴 High |
| **Difficulty** | 🟡 Intermediate |
| **Hunt Time** | ~3 min |

### Why Hunt This

WinRM (5985 HTTP / 5986 HTTPS) powers PowerShell Remoting and is a favorite for stealthy lateral movement (`Enter-PSSession`, `Invoke-Command`, Evil-WinRM). A **workstation** initiating WinRM is rarely legitimate.

**Step 1 — All WinRM flows**

```
event.dataset:zeek.conn AND destination.port:(5985 OR 5986) | groupby source.ip destination.ip
```

**Step 2 — Filter to workstation-originated WinRM**

Cross-reference the source list with inventory. Admin tooling from a management server may be fine; **a user workstation initiating WinRM is a strong lead.**

**Step 3 — Isolate**

```
source.ip:<SOURCE> AND destination.port:(5985 OR 5986)
```

**Look for**

- ✔ Workstation → server/DC WinRM
- ✔ One source → many WinRM targets (fan-out)
- ✔ WinRM immediately after SMB access to the same target (tool drop → remote exec)


### Attack Use

Attackers may use WinRM to execute PowerShell remotely and move through managed Windows systems.

### Attacker Pivot

By this point, the attacker may have learned which managed Windows hosts accept WinRM and remote PowerShell. From **WinRM (5985 / 5986)**, the likely next move is to execute scripts without a desktop and fan out through administrative credentials. For the investigation, pivot to wsmprovhost activity, authentication, command lines, source/target pairs, and destination-side execution.

**Next Pivots**

- → Phase 6 (Lateral Movement) — `wsmprovhost.exe` spawning on the target is 🔴
- → Endpoint: PowerShell launched via `wsmprovhost.exe`
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Config management (Ansible/DSC/Puppet) from known management hosts, admin automation.
- *Suspicious:* Any WinRM originating from a workstation; WinRM fan-out; WinRM + prior SMB to same host.

**Investigation Checklist**

- [ ] Confirm source is not a sanctioned mgmt host
- [ ] Pivot to Endpoint for `wsmprovhost.exe` → child processes
- [ ] Correlate 4624 logon type 3 on target
- [ ] Escalate — high confidence for workstation-origin WinRM

---

## Hunt 21 — SSH to Unexpected Hosts

| | |
|---|---|
| **ATT&CK** | `T1021.004` (SSH) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~3 min |

### Why Hunt This

SSH (22) is normal to Linux/network gear but suspicious to Windows endpoints, in fan-out patterns, or inbound from the internet.

**Step 1 — All SSH flows**

```
event.dataset:zeek.conn AND destination.port:22 | groupby source.ip destination.ip
```

**Step 2 — SSH client/version detail & auth outcome**

```
event.dataset:zeek.ssh | groupby source.ip destination.ip ssh.client ssh.auth.success
```

**Step 3 — Internet-exposed / fan-out SSH**

```
event.dataset:zeek.conn AND destination.port:22 AND NOT source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8"
```

**Look for**

- ✔ SSH to a Windows host (unexpected)
- ✔ One source → many SSH targets
- ✔ Inbound SSH from the internet, or many failed auths → one success (brute force)
- ✔ Unusual SSH client banners


### Attack Use

Attackers may use SSH for remote shells, tunneling, or tool transfer to unexpected systems.

### Attacker Pivot

By this point, the attacker may have learned which unexpected hosts accept SSH and whether long sessions or forwarding work. From **SSH to Unexpected Hosts**, the likely next move is to open a shell, transfer files, add keys, or tunnel toward another subnet. For the investigation, pivot to authentication outcomes, command or process evidence, destination role, long-lived sessions, and port forwarding.

**Next Pivots**

- Brute force then success? → Phase 3 (Initial Access)
- Fan-out? → Phase 6
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Admins → Linux/network devices, CI/CD, jump hosts, git over SSH.
- *Suspicious:* SSH to Windows, internet-exposed SSH, brute-force patterns, odd client strings.

**Investigation Checklist**

- [ ] Confirm target should accept SSH
- [ ] Check auth success/failure ratio
- [ ] Pivot to Endpoint / auth logs
- [ ] Escalate on brute-force success or unexpected target

---

## Hunt 22 — Suricata Alert Triage

| | |
|---|---|
| **ATT&CK** | (varies by signature) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~5 min |

### Why Hunt This

Suricata is your signature-based tripwire. Rather than chasing every alert, triage by *severity* and *category*, then pivot to the IP behind the highest-fidelity hits.

**Step 1 — Group alerts by signature**

```
event.module:suricata | groupby rule.name
```

**Step 2 — Prioritize by severity / category**

```
event.module:suricata AND event.severity:1 | groupby rule.name source.ip destination.ip
```

(Suricata severity 1 = highest. Also filter `rule.category` for `Trojan`, `Exploit`, `Malware`, `Command and Control`.)

**Step 3 — Pivot to the flow behind an alert (via community_id)**

```
network.community_id:"<value from the alert>"
```

This pulls the Zeek conn/http/ssl/dns records for the exact flow that alerted.

**Look for**

- ✔ High-severity or C2/trojan-category signatures
- ✔ The same source/destination across multiple different signatures
- ✔ Alerts that correlate with a rare/beaconing IP from earlier hunts


### Attack Use

A Suricata hit can identify exploit delivery, malware, or C2 traffic that an attacker is actively using.

### Attacker Pivot

By this point, the attacker may have learned which flow triggered a known exploit, malware, or C2 signature. From **Suricata Alert Triage**, the likely next move is to continue the detected behavior, change payloads, or move to infrastructure not covered by the signature. For the investigation, pivot on community ID, signature context, flow records, endpoint process, and related infrastructure before acting.

**Next Pivots**

- Use `network.community_id` to pivot into any Zeek log → **Master IP Pivot**
- ET malware/C2 category? → Phase 8, Phase 10
- → **Master IP Pivot** on source and destination

**Analyst Notes**

- *Normal:* Policy/informational signatures, scanner noise, self-signed-cert alerts on legit internal apps.
- *Suspicious:* Trojan/CnC/Exploit categories, a host hitting many distinct high-sev rules, alert that lines up with prior rarity/timing findings.

**Investigation Checklist**

- [ ] Read the actual signature (don't trust the name alone)
- [ ] Pivot on community_id to the raw flow
- [ ] Confirm direction (inbound attempt vs outbound success)
- [ ] Escalate high-fidelity C2/trojan hits

---

## Hunt 23 — Zeek Weird Logs

| | |
|---|---|
| **ATT&CK** | `T1071`, `T1205` (Traffic Signaling), `T1001` (Data Obfuscation) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🟡 Intermediate |
| **Hunt Time** | ~5 min |

### Why Hunt This

Zeek's `weird` log records protocol violations and things Zeek couldn't parse cleanly — malformed TLS, unexpected protocol on a port, tunneling artifacts. Weird activity clustered on one host is a lead.

**Step 1 — Group weird events by type**

```
event.dataset:zeek.weird | groupby zeek.weird.name
```

**Step 2 — Which hosts generate the odd ones?**

```
event.dataset:zeek.weird AND zeek.weird.name:<name> | groupby source.ip destination.ip
```

**Step 3 — Isolate a host with concentrated weirdness**

```
event.dataset:zeek.weird AND source.ip:<HOST> | groupby zeek.weird.name
```

**Look for**

- ✔ Protocol-on-wrong-port weirds (e.g. non-HTTP on 80, non-TLS on 443) → possible tunneling
- ✔ Malformed / truncated protocol violations concentrated on one pair
- ✔ Weird events lining up with a rare/beaconing destination


### Attack Use

Attackers may generate malformed or protocol-mismatched traffic while tunneling, evading parsing, or using custom tooling.

### Attacker Pivot

By this point, the attacker may have learned which malformed or mismatched traffic reaches its destination. From **Zeek Weird Logs**, the likely next move is to use protocol ambiguity, custom tooling, or tunneling to evade normal parsing. For the investigation, pivot to the host pair, protocol, unusual port, related TLS/HTTP data, and endpoint process.

**Next Pivots**

- Protocol mismatch on a port? → Hunt 24 (TLS anomalies) / Phase 8 (tunneling)
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Buggy apps, load balancers, TLS middleboxes, and some IoT generate steady benign weirds — baseline them.
- *Suspicious:* New weird types from one host, protocol-mismatch weirds, weirds co-located with other Phase 1 findings.

**Investigation Checklist**

- [ ] Baseline which weirds are normal for you
- [ ] Focus on new/concentrated types
- [ ] Pivot on community_id to the flow
- [ ] Escalate with corroboration

---

## Hunt 24 — JA3 / JA3S & TLS Anomalies

| | |
|---|---|
| **ATT&CK** | `T1573` (Encrypted Channel), `T1071.001` (Web Protocols) |
| **Confidence** | 🟡 Medium |
| **Difficulty** | 🔴 Advanced |
| **Hunt Time** | ~15 min |

### Why Hunt This

JA3 fingerprints the TLS *client*; JA3S fingerprints the *server*. Malware TLS stacks (Cobalt Strike, Metasploit, custom implants) often produce rare or known-bad fingerprints, and their certs are frequently self-signed with junk fields.

**Step 1 — Rare client fingerprints**

```
event.dataset:zeek.ssl | groupby tls.client.ja3
```

Sort **ascending** — rare JA3 values (used by one host to one destination) are candidates.

**Step 2 — Profile a rare JA3**

```
event.dataset:zeek.ssl AND tls.client.ja3:"<ja3hash>" | groupby source.ip destination.ip tls.client.server_name
```

**Step 3 — TLS anomalies: self-signed / missing SNI / odd issuers**

```
event.dataset:zeek.ssl AND (tls.client.server_name:"" OR NOT tls.client.server_name:*) | groupby source.ip destination.ip
```

(Also review `zeek.x509` cert issuer/subject for self-signed or nonsense CN values on external destinations.)

**Look for**

- ✔ A rare JA3 used by one host to a hosting/VPS IP
- ✔ TLS to an external IP with no SNI, or a self-signed cert
- ✔ JA3 matching a known offensive-tool fingerprint (compare to threat intel)
- ✔ Rare JA3 + beaconing = strong stack


### Attack Use

Attackers may use uncommon TLS stacks, no-SNI sessions, or suspicious certificates to hide C2 in encryption.

### Attacker Pivot

By this point, the attacker may have learned which TLS fingerprints, certificates, and no-SNI paths are accepted. From **JA3 / JA3S & TLS Anomalies**, the likely next move is to reuse the encrypted channel across hosts or rotate infrastructure while retaining the client. For the investigation, pivot to the JA3/JA3S, certificate, destination, timing, endpoint process, and other hosts with the same fingerprint.

**Next Pivots**

- → Hunt 10 (Beaconing), Hunt 13 (VPS)
- → Phase 8 (C2) for full encrypted-channel analysis
- → **Master IP Pivot**

**Analyst Notes**

- *Normal:* Every browser/app/OS has JA3s; rare ≠ bad. Corporate custom apps produce rare-but-benign JA3s — baseline them.
- *Suspicious:* Rare JA3 to raw VPS, no-SNI TLS to external hosting, self-signed certs outbound, JA3 matching CS/Metasploit intel.

**Investigation Checklist**

- [ ] Record the JA3/JA3S
- [ ] Compare against known-bad fingerprint intel
- [ ] Inspect the x509 cert
- [ ] Pivot to Endpoint for the TLS client process
- [ ] Escalate on intel match or stacked signals

---

## Hunt 25 — IOC Sweep (IP / Domain / URL / Hash / JA3 / UA)

| | |
|---|---|
| **ATT&CK** | (indicator-driven) |
| **Confidence** | 🔴 High (on a true intel match) |
| **Difficulty** | 🟢 Easy |
| **Hunt Time** | ~2 min per indicator |

### Why Hunt This

When you receive an indicator (from intel, a report, or another hunt), sweep all of Security Onion for it in one shot. This is the fastest path from "here's an IOC" to "is it in my network?"

**IP indicator**

```
source.ip:<IOC_IP> OR destination.ip:<IOC_IP>
```

**Domain / FQDN indicator (DNS, TLS SNI, HTTP Host)**

```
dns.question.name:*<ioc_domain>* OR tls.client.server_name:*<ioc_domain>* OR url.domain:*<ioc_domain>*
```

**URL indicator**

```
url.original:*<ioc_path>* OR url.domain:*<ioc_domain>*
```

**File hash indicator (Zeek file analysis)**

```
event.dataset:zeek.files AND (file.hash.sha256:"<sha256>" OR file.hash.md5:"<md5>" OR file.hash.sha1:"<sha1>")
```

**JA3 / JA3S indicator**

```
tls.client.ja3:"<ja3>" OR tls.server.ja3s:"<ja3s>"
```

**User-Agent indicator**

```
user_agent.original:"*<ioc_user_agent>*"
```

**Look for**

- ✔ Any hit at all — a match on a curated IOC is high confidence by definition
- ✔ Which internal host(s) touched the indicator, and when (first/last seen)
- ✔ Whether the contact succeeded (`connection.state:SF`, HTTP 200, resolved answer)


### Attack Use

A confirmed IOC can reveal active infrastructure, payloads, or related artifacts used by an attacker.

### Attacker Pivot

By this point, the attacker may have learned which known indicator is present, on which hosts, and during which stage. From **IOC Sweep (IP / Domain / URL / Hash / JA3 / UA)**, the likely next move is to continue on already affected systems, rotate the exposed indicator, or reuse connected infrastructure. For the investigation, pivot from every match to the host, process, account, first/last seen, and connected indicators to scope the full operation.

**Next Pivots**

- Any hit → **Master IP Pivot** on the involved internal host(s)
- Hash hit → Phase 10 (Malware) + Endpoint
- Domain/URL hit → Phase 8 (C2)

**Analyst Notes**

- *Normal:* Stale/low-quality intel produces false hits (recycled IPs, shared CDNs). Weight by indicator quality and recency.
- *Suspicious:* A match on a specific, well-sourced indicator — especially a hash or a full URL — is actionable immediately.

**Investigation Checklist**

- [ ] Record which indicator matched and where
- [ ] Establish first-seen / last-seen
- [ ] Confirm the contact succeeded
- [ ] Pivot to Endpoint on any matched host
- [ ] Escalate on high-quality matches

---

# The Master IP Pivot

> **You just found an IP. Now what?** Run it through this fixed chain, top to bottom. Don't improvise the order — the order is the value. (Phase 2 expands each step into a full playbook.)

Set your example IP once and reuse it:

```
source.ip:<IP> OR destination.ip:<IP>
```

### The chain

```
EVERYTHING
   ↓
DNS        (what names did it use / resolve to?)
   ↓
HTTP       (hosts, URIs, user-agents, downloads)
   ↓
TLS        (SNI, JA3/JA3S, certs)
   ↓
SMB        (shares, file transfer, admin shares)
   ↓
RDP        (remote desktop reach)
   ↓
WinRM      (remote PowerShell)
   ↓
SURICATA   (signature hits on this IP)
   ↓
ENDPOINT   (the process behind the traffic)
```

### Copy/paste pivot queries

**0. Everything for this IP**

```
source.ip:<IP> OR destination.ip:<IP>
```

**1. DNS — names associated with the IP**

```
event.dataset:zeek.dns AND (source.ip:<IP> OR dns.answers:<IP>)
```

**2. HTTP — requests to/from the IP**

```
event.dataset:zeek.http AND (source.ip:<IP> OR destination.ip:<IP>)
```

**3. TLS — encrypted sessions and fingerprints**

```
event.dataset:zeek.ssl AND (source.ip:<IP> OR destination.ip:<IP>)
```

**4. SMB — shares and file movement**

```
(event.dataset:zeek.smb_mapping OR event.dataset:zeek.smb_files) AND (source.ip:<IP> OR destination.ip:<IP>)
```

**5. RDP — remote desktop**

```
event.dataset:zeek.conn AND destination.port:3389 AND (source.ip:<IP> OR destination.ip:<IP>)
```

**6. WinRM — remote PowerShell**

```
event.dataset:zeek.conn AND destination.port:(5985 OR 5986) AND (source.ip:<IP> OR destination.ip:<IP>)
```

**7. Suricata — signature hits**

```
event.module:suricata AND (source.ip:<IP> OR destination.ip:<IP>)
```

**8. Endpoint — the process behind it**

```
event.module:(endgame OR sysmon OR windows_eventlog) AND (source.ip:<IP> OR destination.ip:<IP>)
```

*(Endpoint dataset names depend on what you ship into Security Onion — Elastic Agent/Endgame, Sysmon via Winlogbeat, etc. Adjust `event.module`/`event.dataset` to match your deployment.)*

### At the end of the Master IP Pivot you should be able to answer

- Is this host compromised?
- Who did it talk to?
- What protocol?
- Did authentication occur?
- Was PowerShell launched?
- Was malware downloaded?
- Was data exfiltrated?

If any answer is "yes / unclear," continue into the tactic-specific phases below.

---

# Phase 1 Flowcharts

### Master decision tree

```
ALERT / LEAD
     │
     ▼
Do you already have an IP? ──No──► Run a Phase 1 hunt (1–25) to GET one
     │
    Yes
     │
     ▼
MASTER IP PIVOT  (DNS→HTTP→TLS→SMB→RDP→WinRM→Suricata→Endpoint)
     │
     ▼
What did you find?
 ├─ SMB admin-share tool drop ........► Phase 6 (Lateral Movement)
 ├─ WinRM / wsmprovhost.exe ..........► Phase 6 + Endpoint
 ├─ Beaconing / rare JA3 / C2 sig ....► Phase 8 (Command & Control)
 ├─ Large upload / cloud storage .....► Phase 9 (Exfiltration)
 ├─ Downloaded executable / LOLBin ...► Phase 10 (Malware)
 ├─ Logon anomalies (4624/4625) ......► Phase 11 (Active Directory)
 └─ Nothing actionable ...............► Document & close
```

### "If you found X" quick router

```
Found SMB?        → Hunt 18 → Phase 6
Found RDP?        → Hunt 19 → Phase 11 (4624 type 10)
Found WinRM?      → Hunt 20 → Phase 6 (wsmprovhost.exe)
Found DNS oddity? → Hunt 15/16/17 → Phase 8
Found Beaconing?  → Hunt 10 → Phase 8
Found a rare IP?  → Hunt 1/3/13 → Master IP Pivot
Found an IOC?     → Hunt 25 → Master IP Pivot
```

### The protocol pivot (memorize this)

```
Everything → DNS → HTTP → TLS → SMB → RDP → WinRM → Suricata → Endpoint
```

---

# Phase 1 Quick Reference

### The five queries you'll use most

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.ip
```

```
source.ip:<IP> OR destination.ip:<IP>
```

```
event.dataset:zeek.dns AND dns.answers:<IP>
```

```
event.module:suricata AND event.severity:1 | groupby rule.name source.ip destination.ip
```

```
network.community_id:"<value>"
```

### Ports at a glance

| Port | Service | Hunt |
|---|---|---|
| 445 | SMB | 18 |
| 3389 | RDP | 19 |
| 5985 / 5986 | WinRM | 20 |
| 22 | SSH | 21 |
| 135 | RPC/DCOM | 4 |
| 389 / 636 | LDAP / LDAPS | 4 |
| 88 | Kerberos | (Phase 5) |
| 1433 | MSSQL | (Phase 3) |
| 21 / 20 | FTP | (Phase 9) |
| 53 | DNS | 16, 17 |
| 80 / 443 | HTTP / HTTPS | 8, 24 |
| 9001 / 9030 / 9050 | TOR | 14 |

### Connection states (Zeek `connection.state`) cheat sheet

| State | Meaning | Hunting signal |
|---|---|---|
| `SF` | Normal establish + close | Successful comms |
| `S0` | SYN, no reply | Scanning (at scale) |
| `REJ` | Connection rejected | Scanning / closed port |
| `RSTO` / `RSTR` | Reset by originator / responder | Aborted / probing |
| `OTH` | No SYN seen (mid-stream) | Long-lived / asymmetric routing |

### Rarity workflow (the one move)

```
1.  | groupby <field>
2.  sort ASCENDING  →  bottom rows = rare = leads
3.  source.ip:<IP> OR destination.ip:<IP>
4.  Master IP Pivot
```

### Dynamic-DNS & anonymizer domains to watch

```
*duckdns.org  *no-ip.com  *ddns.net  *hopto.org  *sytes.net
*zapto.org  *myftp.org  *serveo.net  *ngrok.io  *trycloudflare.com
```

### Known DoH endpoints to watch

```
dns.google  cloudflare-dns.com  mozilla.cloudflare-dns.com
dns.quad9.net  doh.opendns.com  dns.nextdns.io  dns.adguard.com
```

---

*End of Phase 1. Next: **Phase 2 — Investigate the Suspicious IP (Master IP Pivot expanded).***

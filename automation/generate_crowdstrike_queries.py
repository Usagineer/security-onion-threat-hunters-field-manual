from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "queries" / "security-onion"
DESTINATION = ROOT / "queries" / "crowdstrike"


PROCESS_PATTERNS = {
    "whoami": r"(\\whoami\.exe$|\bwhoami\b|\bid\s+-[ug])",
    "hostname-ipconfig": r"(\\hostname\.exe$|\\ipconfig\.exe$|\bhostname\b|\bipconfig\b|ifconfig|ip\s+addr)",
    "arp-route": r"(\\arp\.exe$|\\route\.exe$|\barp\s+-a\b|\broute\s+print\b|ip\s+(neigh|route))",
    "systeminfo": r"(\\systeminfo\.exe$|\bsysteminfo\b|Get-ComputerInfo|uname\s+-a|lsb_release)",
    "net-user-group": r"(\\net1?\.exe$.*\b(user|group|localgroup)\b|Get-(LocalUser|LocalGroup|ADUser|ADGroup))",
    "nltest": r"(\\nltest\.exe$|\bnltest\b|Get-ADDomain|Get-ADTrust|Get-ADDomainController)",
    "netstat": r"(\\netstat\.exe$|\bnetstat\b|Get-NetTCPConnection|\bss\s+-|\blsof\s+-i)",
    "tasklist": r"(\\tasklist\.exe$|\btasklist\b|Get-Process|\bps\s+(aux|ef))",
    "quser-query-user": r"(\\quser\.exe$|\\query\.exe$.*\buser\b|\bquser\b|\bquery\s+user\b|Win32_LogonSession)",
    "powershell-discovery": r"(Get-(ComputerInfo|NetIPConfiguration|NetTCPConnection|LocalUser|LocalGroup|ADUser|ADGroup|ADDomain)|Resolve-DnsName|Test-NetConnection)",
    "network-service-enumeration": r"(nmap|masscan|portqry|Test-NetConnection|tnc\s+.+-Port|nc\s+(-z|.*-v))",
    "icmp-and-subnet-discovery": r"(ping\.exe|fping|nmap.*-sn|for\s+.*\bin\b.*ping|Test-Connection)",
    "lsass-access": r"(lsass|comsvcs\.dll.*MiniDump|sekurlsa|nanodump|dumpert)",
    "mimikatz": r"(mimikatz|sekurlsa::|lsadump::|kerberos::|privilege::debug)",
    "kerberoasting": r"(Rubeus.*kerberoast|Invoke-Kerberoast|GetUserSPNs|setspn.*-Q)",
    "asrep-roasting": r"(Rubeus.*asreproast|GetNPUsers|Invoke-ASREPRoast)",
    "procdump": r"(procdump.*(lsass|-ma)|rundll32.*comsvcs.*MiniDump)",
    "sam": r"(reg(\.exe)?.*save.*HKLM\\SAM|reg(\.exe)?.*save.*HKLM\\SYSTEM|\\config\\SAM|esentutl.*SAM)",
    "ntds-dit": r"(ntds\.dit|ntdsutil.*ifm|vssadmin.*create.*shadow|esentutl.*ntds)",
    "registry-hive-and-sql-shell": r"(reg(\.exe)?.*(save|export).*HKLM|xp_cmdshell|sp_configure.*xp_cmdshell)",
    "psexec": r"(psexec|psexesvc|\\ADMIN\$|accepteula.*\\\\)",
    "wmi": r"(wmic.*\/node:.*process.*call.*create|Invoke-WmiMethod|Invoke-CimMethod|WmiCreateProcess)",
    "winrm": r"(Enter-PSSession|Invoke-Command.*-ComputerName|New-PSSession|winrs(\.exe)?|WSMan:)",
    "remote-services": r"(sc(\.exe)?.*\\\\.+\s+(create|config|start)|New-Service|CreateService)",
    "scheduled-tasks": r"(schtasks.*\/(create|run)|Register-ScheduledTask|New-ScheduledTaskAction)",
    "dcom": r"(MMC20\.Application|ShellWindows|ShellBrowserWindow|DCOM.*ComputerName)",
    "registry-run-keys": r"(reg(\.exe)?.*(add|import).*(CurrentVersion\\Run|RunOnce)|Set-ItemProperty.*CurrentVersion\\Run)",
    "startup-folder": r"(\\Start Menu\\Programs\\Startup\\|shell:startup|shell:common startup)",
    "services": r"(sc(\.exe)?.*(create|config)|New-Service|Set-Service.*BinaryPathName)",
    "bits-jobs": r"(bitsadmin.*\/(create|addfile|setnotifycmdline|resume)|Start-BitsTransfer|Add-BitsFile)",
    "com-hijacking": r"(HKCU\\Software\\Classes\\CLSID|InprocServer32|LocalServer32)",
    "linux-cron-and-temp-execution": r"((crontab|cron).*(\/tmp|\/var\/tmp|\/dev\/shm)|\/(tmp|var\/tmp|dev\/shm)\/\S+)",
    "proxy-and-reverse-tunnel": r"(chisel|ligolo|frp(c|s)?|ngrok|cloudflared|socat|plink.*-[RLDP]|ssh.*-[RLND]|netsh.*portproxy)",
    "ftp": r"(\\ftp\.exe$|\bftp\s+|lftp|curl.*ftp:)",
    "sftp": r"(\\sftp\.exe$|\bsftp\s+|psftp)",
    "scp": r"(\\scp\.exe$|\bscp\s+|pscp)",
    "archive-creation": r"(7z(\.exe)?.*\s+a\s+|rar(\.exe)?.*\s+a\s+|Compress-Archive|tar\s+(-c|.*cz)|makecab)",
    "database-collection": r"(mysqldump|pg_dump|sqlcmd.*(-o|queryout)|bcp.*queryout|mongoexport|expdp)",
    "lolbins": r"(certutil|bitsadmin|mshta|rundll32|regsvr32|installutil|regasm|regsvcs|msbuild|cscript|wscript|wmic)\.exe",
    "certutil": r"(certutil\.exe.*(-urlcache|-decode|-decodehex|-split))",
    "bitsadmin": r"(bitsadmin\.exe.*\/(transfer|create|addfile|setnotifycmdline|resume))",
    "mshta": r"(mshta\.exe.*(https?:|javascript:|vbscript:|\.hta))",
    "rundll32": r"(rundll32\.exe.*(javascript:|http|url\.dll|shell32\.dll|comsvcs\.dll))",
    "regsvr32": r"(regsvr32\.exe.*(\/i:|scrobj\.dll|http))",
    "encodedcommand": r"(powershell(_ise)?\.exe.*(-enc|-encodedcommand)\s+)",
    "downloadstring": r"(DownloadString|DownloadFile|WebClient|Invoke-WebRequest|Start-BitsTransfer)",
    "iex": r"(\bIEX\b|Invoke-Expression)",
    "defense-impairment-powershell": r"(Set-MpPreference.*Disable|Add-MpPreference.*Exclusion|Set-NetFirewallProfile.*False|Set-ExecutionPolicy.*Bypass)",
    "defense-evasion-and-unix-masquerade": r"(wevtutil.*cl|Clear-EventLog|Set-MpPreference.*Disable|history\s+-c|unset\s+HISTFILE|touch\s+-[amrt]|chattr\s+\+i)",
}


PORTS = {
    "smb": "445",
    "rdp": "3389",
    "winrm": "(5985|5986)",
    "ssh": "22",
    "mssql": "1433",
    "ftp": "(20|21)",
}


DNS_FILTERS = {
    "dynamic-dns": r"DomainName=/\.(duckdns|ddns|dynu|no-ip|hopto|servehttp|zapto|dnsdynamic)\./i",
    "dns-over-https-doh": r"DomainName=/(dns\.google|cloudflare-dns\.com|dns\.quad9\.net|doh\.opendns\.com)$/i",
    "cloud-storage": r"DomainName=/(dropbox|drive\.google|onedrive|sharepoint|box|mega|pcloud|sync)\./i",
    "onedrive": r"DomainName=/(onedrive|sharepoint|1drv)\./i",
    "dropbox": r"DomainName=/(dropbox\.com|dropboxapi\.com|dropboxusercontent\.com)$/i",
    "mega": r"DomainName=/(mega\.nz|mega\.io|mega\.co\.nz)$/i",
    "google-drive": r"DomainName=/(drive\.google\.com|docs\.google\.com|googleapis\.com|googleusercontent\.com)$/i",
}


OT_FILTERS = {
    "modbus": ("network.protocol=/^modbus$/i OR destination.port=502", "modbus.function"),
    "ethernet-ip": ("network.protocol=/^(ethernet-ip|enip)$/i OR destination.port=/^(44818|2222)$/", "destination.port"),
    "cip": ("network.protocol=/^cip$/i OR cip.service=*", "cip.service"),
    "dnp3": ("network.protocol=/^dnp3$/i OR destination.port=20000", "dnp3.function"),
    "bacnet": ("network.protocol=/^bacnet$/i OR destination.port=47808", "bacnet.service"),
    "opc-ua": ("network.protocol=/^opc-ua$/i OR destination.port=4840", "opcua.service"),
    "s7": ("network.protocol=/^(s7|s7comm)$/i OR destination.port=102", "s7.function"),
    "engineering-workstations": (
        "(host.type=/engineering/i OR source.asset.type=/engineering/i) | destination.port=/^(102|502|4840|20000|44818|47808)$/",
        "source.asset.name",
    ),
    "plc-programming": (
        "(event.action=/program|download|write|start|stop|reset|force/i OR ot.operation=/program|download|write|start|stop|reset|force/i)",
        "event.action",
    ),
    "unauthorized-controllers": (
        "destination.port=/^(102|502|4840|20000|44818|47808)$/",
        "observer.name",
    ),
    "it-ot-boundary-and-hmi-impact": (
        "(source.zone=/^IT$/i destination.zone=/^OT$/i) OR host.type=/^(hmi|historian|engineering)$/i",
        "destination.zone",
    ),
}


PHASE_PURPOSE = {
    "phase-01-find-suspicious-ips": "surface anomalous network infrastructure and communication patterns",
    "phase-02-investigate-the-ip": "scope an IP lead across independent telemetry",
    "phase-03-initial-access": "identify how an attacker may have entered the environment",
    "phase-04-discovery": "identify commands used to learn the host, users, domain, and network",
    "phase-05-credential-access": "identify attempts to obtain reusable credentials or directory secrets",
    "phase-06-lateral-movement": "identify movement from one system or account to another",
    "phase-07-persistence": "identify mechanisms that preserve attacker access",
    "phase-08-command-and-control": "identify covert or recurring command-and-control channels",
    "phase-09-exfiltration": "identify staging and transfer of collected data",
    "phase-10-malware-execution": "identify suspicious execution and defense evasion",
    "phase-11-active-directory": "investigate Windows and Active Directory security events",
    "phase-12-ics-ot": "identify unsafe or unauthorized industrial-control activity",
    "phase-13-ioc-hunting": "scope a known indicator across the estate",
    "phase-14-pivot-cheat-sheets": "continue from a confirmed lead into its surrounding activity",
}


def humanize(slug: str) -> str:
    return re.sub(r"^\d+-", "", slug).replace("-", " ")


def native_process(pattern: str, platform: str = "Win") -> list[str]:
    return [
        fr"""#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform={platform}
| ImageFileName=/{pattern}/i OR CommandLine=/{pattern}/i
| table([@timestamp, aid, ComputerName, UserSid, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData], limit=2000)""",
        fr"""#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform={platform}
| ImageFileName=/{pattern}/i OR CommandLine=/{pattern}/i
| groupBy([aid, ParentBaseFileName, ImageFileName], function=[count(as=executions), collect(CommandLine, limit=20)], limit=max)
| sort(executions, order=descending, limit=1000)""",
    ]


def native_network(port: str, extra: str = "") -> list[str]:
    suffix = f" | {extra}" if extra else ""
    return [
        fr"""#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4)$/
| RemotePort=/^{port}$/{suffix}
| table([@timestamp, aid, ContextProcessId, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, Protocol], limit=2000)""",
        fr"""#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4)$/
| RemotePort=/^{port}$/{suffix}
| groupBy([RemoteAddressIP4, RemotePort], function=[count(as=connections), count(aid, distinct=true, as=endpoints)], limit=max)
| sort(connections, order=descending, limit=1000)""",
    ]


def normalized_network(filter_text: str, extra_group: str = "destination.port") -> list[str]:
    return [
        f"""{filter_text}
| table([@timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, network.protocol, network.bytes, event.action, host.name, user.name], limit=2000)""",
        f"""{filter_text}
| groupBy([source.ip, destination.ip, {extra_group}], function=[count(as=events), sum(network.bytes, as=bytes)], limit=max)
| sort(events, order=descending, limit=1000)""",
    ]


def dns(filter_text: str = "DomainName=*") -> list[str]:
    return [
        fr"""#event_simpleName=DnsRequest
| {filter_text}
| table([@timestamp, aid, ComputerName, ContextProcessId, DomainName, RequestType], limit=2000)""",
        fr"""#event_simpleName=DnsRequest
| {filter_text}
| groupBy(DomainName, function=[count(as=requests), count(aid, distinct=true, as=endpoints)], limit=max)
| sort(endpoints, order=ascending, limit=1000)""",
    ]


def ip_pivot() -> list[str]:
    return [
        r"""#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4|UserLogon|UserLogonFailed2|RemoteBruteForceDetectInfo|TlsClientHello)$/
| RemoteAddressIP4=?{ip=*}
| table([@timestamp, #event_simpleName, aid, UserName, ContextProcessId, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort], limit=5000)""",
        r"""#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4|UserLogon|UserLogonFailed2|RemoteBruteForceDetectInfo|TlsClientHello)$/
| RemoteAddressIP4=?{ip=*}
| groupBy([#event_simpleName, aid], function=count(as=events), limit=max)
| sort(events, order=descending, limit=1000)""",
    ]


def queries_for(phase: str, slug: str) -> tuple[str, list[str], list[str]]:
    topic_slug = re.sub(r"^\d+-", "", slug)
    notes = [
        "Set an explicit time range and validate the returned fields against a representative raw event.",
        "Baseline approved administration, service accounts, infrastructure, and host roles before adding exclusions.",
    ]

    if phase == "phase-04-discovery":
        return "Falcon endpoint process telemetry", native_process(PROCESS_PATTERNS[topic_slug]), notes

    if phase in {"phase-05-credential-access", "phase-06-lateral-movement", "phase-07-persistence", "phase-10-malware-execution"} and topic_slug in PROCESS_PATTERNS:
        platform = "Lin" if topic_slug == "linux-cron-and-temp-execution" else "Win"
        return "Falcon endpoint process telemetry", native_process(PROCESS_PATTERNS[topic_slug], platform), notes

    if phase == "phase-01-find-suspicious-ips":
        if slug == "00-master-ip-pivot":
            return "Falcon endpoint telemetry; set the `ip` CQL parameter", ip_pivot(), notes
        if slug == "01-rare-destination-ip":
            return "Falcon `NetworkConnectIP4` telemetry", [r"""#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| groupBy(RemoteAddressIP4, function=[count(as=connections), count(aid, distinct=true, as=endpoints), collect([aid, RemotePort], limit=50)], limit=max)
| endpoints<=3
| sort(connections, order=ascending, limit=1000)"""], notes
        if slug == "02-rare-source-ip":
            return "Falcon inbound network and logon telemetry", [r"""#event_simpleName=/^(NetworkReceiveAcceptIP4|UserLogon|UserLogonFailed2)$/
| RemoteAddressIP4=*
| groupBy(RemoteAddressIP4, function=[count(as=events), count(aid, distinct=true, as=endpoints), collect([aid, LocalPort, UserName], limit=50)], limit=max)
| endpoints<=3
| sort(events, order=ascending, limit=1000)"""], notes
        if slug == "03-new-first-seen-external-ip":
            return "Falcon `NetworkConnectIP4` telemetry", [r"""#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| groupBy(RemoteAddressIP4, function=[min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen), count(aid, distinct=true, as=endpoints)], limit=max)
| sort(firstSeen, order=descending, limit=1000)"""], notes
        if slug == "04-one-host-many-hosts":
            return "Falcon `NetworkConnectIP4` telemetry", [r"""#event_simpleName=NetworkConnectIP4
| groupBy(aid, function=[count(RemoteAddressIP4, distinct=true, as=remoteHosts), count(as=connections), collect([RemoteAddressIP4, RemotePort], limit=100)], limit=max)
| remoteHosts>=25
| sort(remoteHosts, order=descending, limit=1000)"""], notes
        if slug == "05-many-hosts-one-destination":
            return "Falcon `NetworkConnectIP4` telemetry", [r"""#event_simpleName=NetworkConnectIP4
| groupBy([RemoteAddressIP4, RemotePort], function=[count(aid, distinct=true, as=endpoints), count(as=connections)], limit=max)
| endpoints>=10
| sort(endpoints, order=descending, limit=1000)"""], notes
        if slug == "06-one-host-many-ports":
            return "Falcon `NetworkConnectIP4` telemetry", [r"""#event_simpleName=NetworkConnectIP4
| groupBy([aid, RemoteAddressIP4], function=[count(RemotePort, distinct=true, as=ports), count(as=connections), collect(RemotePort, limit=100)], limit=max)
| ports>=10
| sort(ports, order=descending, limit=1000)"""], notes
        if slug in {"07-large-outbound-transfer", "08-large-inbound-transfer"}:
            field = "source.bytes" if "outbound" in slug else "destination.bytes"
            return "Normalized firewall, proxy, or flow telemetry", normalized_network(f"{field}>=100000000"), notes
        if slug == "09-long-lived-connections":
            return "Normalized network telemetry; ECS `event.duration` is nanoseconds", normalized_network("event.duration>=3600000000000"), notes
        if slug == "10-beaconing":
            return "Falcon `NetworkConnectIP4` telemetry", [r"""#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| bucket(span=5m, field=[aid, RemoteAddressIP4, RemotePort], function=count(as=connections), limit=max)
| connections>=2
| groupBy([aid, RemoteAddressIP4, RemotePort], function=[count(as=activeBuckets), avg(connections, as=avgPerBucket), stdDev(connections, as=jitter)], limit=max)
| activeBuckets>=6
| sort(jitter, order=ascending, limit=1000)"""], notes
        if slug == "11-servers-iot-to-internet":
            return "Normalized network telemetry with asset-role enrichment", normalized_network('(host.type=/^(server|iot|embedded)$/i OR observer.type=/^(server|iot)$/i) | !cidr(destination.ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])'), notes
        if slug == "12-rare-countries":
            return "Falcon network telemetry and `ipLocation()`", [r"""#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| ipLocation(RemoteAddressIP4)
| groupBy(RemoteAddressIP4.country, function=[count(as=connections), count(aid, distinct=true, as=endpoints), collect(RemoteAddressIP4, limit=50)], limit=max)
| sort(connections, order=ascending, limit=250)"""], notes
        if slug == "13-cloud-vps-providers":
            return "Falcon network telemetry and `asn()`", [r"""#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| asn:=asn(RemoteAddressIP4)
| asn.org=/(amazon|google|microsoft|digitalocean|linode|akamai|ovh|vultr|hetzner|choopa)/i
| groupBy([RemoteAddressIP4, asn.org, RemotePort], function=[count(as=connections), count(aid, distinct=true, as=endpoints)], limit=max)"""], notes
        if slug == "14-tor":
            return "Normalized network and process telemetry", normalized_network(r'(destination.port=/^(9001|9030|9040|9050|9051|9150)$/ OR process.name=/^(tor|obfs4proxy)\.exe$/i)'), notes
        if topic_slug in DNS_FILTERS:
            return "Falcon `DnsRequest` telemetry", dns(DNS_FILTERS[topic_slug]), notes
        if slug == "17-rogue-external-dns":
            return "Falcon network telemetry", native_network("53", 'RemoteAddressIP4!=/^(10\\.0\\.0\\.10|10\\.0\\.0\\.11)$/'), notes + ["Replace the example resolver IPs with the approved resolver set."]
        if slug in {"18-smb-exposure", "19-rdp-reach-exposure", "20-winrm", "21-ssh-unexpected-hosts"}:
            port = {"18-smb-exposure": "445", "19-rdp-reach-exposure": "3389", "20-winrm": "(5985|5986)", "21-ssh-unexpected-hosts": "22"}[slug]
            return "Falcon network telemetry", native_network(port), notes
        if slug == "22-suricata-alert-triage":
            return "Suricata telemetry normalized to CPS/ECS", normalized_network("#event.module=suricata event.kind=alert", "rule.name"), notes
        if slug == "23-zeek-weird-logs":
            return "Zeek/Corelight telemetry normalized to CPS/ECS", normalized_network("#event.dataset=/zeek\\.weird/i", "event.reason"), notes
        if slug == "24-ja3-tls-anomalies":
            return "Falcon `TlsClientHello` or normalized TLS telemetry", [r"""#event_simpleName=TlsClientHello
| JA3Hash=*
| groupBy(JA3Hash, function=[count(as=handshakes), count(aid, distinct=true, as=endpoints), collect([RemoteAddressIP4, ServerName], limit=50)], limit=max)
| endpoints<=3
| sort(handshakes, order=ascending, limit=1000)"""], notes
        if slug == "25-ioc-sweep":
            return "Normalized network telemetry and Falcon Intelligence `ioc:lookup()`", ["""source.ip=* OR destination.ip=*
| ioc:lookup([source.ip, destination.ip], type="ip_address", confidenceThreshold=unverified, strict=true)
| split(ioc)
| table([@timestamp, source.ip, destination.ip, destination.port, host.name, user.name, ioc.indicator, ioc.malicious_confidence, ioc.labels], limit=2000)"""], notes

    if phase == "phase-02-investigate-the-ip":
        if slug == "00-everything":
            return "Falcon endpoint telemetry; set the `ip` parameter", ip_pivot(), notes
        if slug in {"01-smb", "02-rdp", "03-winrm"}:
            port = {"01-smb": "445", "02-rdp": "3389", "03-winrm": "(5985|5986)"}[slug]
            return "Falcon endpoint network telemetry; set the `ip` parameter", native_network(port, "RemoteAddressIP4=?{ip=*}"), notes
        if slug == "04-dns":
            return "Falcon `DnsRequest` telemetry", dns(), notes + ["Add the `aid` and `ContextProcessId` obtained from the IP pivot."]
        if slug in {"05-http", "06-tls", "07-suricata"}:
            selector = {"05-http": "network.protocol=/^http$/i OR url.full=*", "06-tls": "network.protocol=/^tls$/i OR tls.server.name=*", "07-suricata": "#event.module=suricata event.kind=alert"}[slug]
            return "Normalized HTTP, TLS, or Suricata telemetry; set the `ip` parameter", normalized_network(f"({selector}) | source.ip=?{{ip=*}} OR destination.ip=?{{ip=*}}"), notes
        return "Falcon endpoint telemetry; set the `ip` parameter", ip_pivot(), notes

    if phase == "phase-03-initial-access":
        if slug == "01-rdp":
            return "Falcon logon telemetry", [r"""#event_simpleName=/^(UserLogon|UserLogonFailed2|RemoteBruteForceDetectInfo)$/ event_platform=Win
| LogonType="10"
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| groupBy([RemoteAddressIP4, UserName, aid, #event_simpleName], function=count(as=events), limit=max)"""], notes
        if slug == "02-vpn":
            return "Normalized VPN authentication telemetry", normalized_network("event.category=authentication (event.action=/vpn/i OR service.name=/vpn/i)", "event.outcome"), notes
        if slug == "03-ssh":
            return "Falcon Linux logon telemetry", [r"""#event_simpleName=/^(UserLogon|UserLogonFailed2)$/ event_platform=Lin
| RemoteAddressIP4=*
| groupBy([RemoteAddressIP4, UserName, aid, #event_simpleName], function=count(as=events), limit=max)"""], notes
        if slug in {"04-web-attacks", "11-web-shell-and-server-side-rce"}:
            if slug == "11-web-shell-and-server-side-rce":
                query = r"""#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ParentBaseFileName=/^(w3wp|httpd|nginx|apache|tomcat|java)\.exe$/i
| ImageFileName=/\\(cmd|powershell|pwsh|cscript|wscript|rundll32|whoami|net|nltest|certutil)\.exe$/i
| table([@timestamp, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData], limit=2000)"""
                return "Falcon process telemetry on web servers", [query], notes
            return "Normalized web server or reverse-proxy telemetry", normalized_network(r"url.original=/(\.\.\/|union(\+|%20|\s)+select|<script|\/etc\/passwd|cmd=|powershell|%2e%2e|jndi:)/i", "url.path"), notes
        if slug in {"05-smb", "06-mssql", "07-ftp"}:
            port = {"05-smb": "445", "06-mssql": "1433", "07-ftp": "(20|21)"}[slug]
            return "Normalized network and authentication telemetry", normalized_network(f"destination.port=/^{port}$/", "event.outcome"), notes
        if slug in {"08-email", "09-phishing"}:
            return "Normalized secure-email-gateway telemetry", [r"""event.category=email
| (email.attachments[].file.name=/\.(iso|img|lnk|js|vbs|hta|chm|xll|one|zip|rar)$/i OR url.full=* OR event.outcome=/fail|blocked/i)
| table([@timestamp, source.ip, email.from.address, email.to.address, email.subject, email.attachments[].file.name, url.full, event.action, event.outcome], limit=2000)"""], notes
        if slug == "10-drive-by-downloads":
            return "Falcon file-write telemetry", [r"""#event_simpleName=/^(PeFileWritten|NewExecutableWritten|NewScriptWritten|JarFileWritten|ZipFileWritten)$/
| TargetFileName=/\\(Downloads|AppData\\Local\\Temp|INetCache)\\/i
| table([@timestamp, aid, ContextProcessId, TargetFileName, SHA256HashData, FileName, Size], limit=2000)"""], notes

    if phase == "phase-05-credential-access" and slug == "03-dcsync":
        return "Falcon `DCSyncAttempted` telemetry", [r"""#event_simpleName=DCSyncAttempted
| groupBy([aid, UserName, RemoteAddressIP4], function=[count(as=attempts), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)], limit=max)
| sort(attempts, order=descending, limit=1000)"""], notes

    if phase == "phase-06-lateral-movement":
        if slug == "01-smb":
            return "Falcon SMB and network telemetry", [r"""#event_simpleName=/^(ProcessExecOnSMBFile|SmbServerShareOpenedEtw|NetworkConnectIP4)$/
| (#event_simpleName!=NetworkConnectIP4 OR RemotePort=445)
| groupBy([#event_simpleName, aid, RemoteAddressIP4], function=[count(as=events), collect([FileName, ShareName, ContextProcessId], limit=50)], limit=max)"""], notes
        if slug == "05-rdp":
            return "Falcon RDP and logon telemetry", [r"""#event_simpleName=/^(UserLogon|ProcessExecOnRDPFile)$/ event_platform=Win
| (#event_simpleName!=UserLogon OR LogonType="10")
| groupBy([UserName, RemoteAddressIP4, aid, #event_simpleName], function=count(as=events), limit=max)"""], notes
        if slug == "09-valid-account-spread":
            return "Falcon `UserLogon` telemetry", [r"""#event_simpleName=UserLogon
| bucket(span=30m)
| groupBy([UserName, _bucket], function=[count(aid, distinct=true, as=endpoints), count(RemoteAddressIP4, distinct=true, as=sources), collect([aid, RemoteAddressIP4, LogonType], limit=100)], limit=max)
| endpoints>=5
| sort(endpoints, order=descending, limit=1000)"""], notes

    if phase == "phase-07-persistence" and slug == "04-wmi-events":
        return "Falcon WMI telemetry", [r"""#event_simpleName=/^(WmiFilterConsumerBinding|WmiEventConsumer|WmiEventFilter|WmiCreateProcess)$/
| groupBy([#event_simpleName, aid], function=[count(as=events), collect([ConsumerName, FilterName, CommandLine, ImageFileName], limit=50)], limit=max)"""], notes

    if phase == "phase-08-command-and-control":
        if slug == "01-beaconing":
            return queries_for("phase-01-find-suspicious-ips", "10-beaconing")
        if slug == "02-dns-tunneling":
            return "Falcon `DnsRequest` telemetry", [r"""#event_simpleName=DnsRequest
| entropy:=shannonEntropy(DomainName)
| length:=length(DomainName)
| groupBy([DomainName, entropy, length], function=[count(as=requests), count(aid, distinct=true, as=endpoints)], limit=max)
| entropy>=3.5 length>=50
| sort(requests, order=descending, limit=1000)"""], notes
        if slug == "03-long-connections":
            return "Normalized network telemetry", normalized_network("event.duration>=3600000000000"), notes
        if slug in {"04-ja3", "08-tls"}:
            return "Falcon `TlsClientHello` telemetry", [r"""#event_simpleName=TlsClientHello
| groupBy([ServerName, JA3Hash, CertificateIssuer], function=[count(as=handshakes), count(aid, distinct=true, as=endpoints), collect(RemoteAddressIP4, limit=50)], limit=max)
| endpoints<=3
| sort(handshakes, order=ascending, limit=1000)"""], notes
        if slug == "05-rare-domains":
            return "Falcon `DnsRequest` telemetry", dns(), notes
        if slug == "06-user-agents":
            return "Normalized proxy or HTTP telemetry", ["""user_agent.original=*
| groupBy(user_agent.original, function=[count(as=requests), count(source.ip, distinct=true, as=sources), collect([url.domain, source.ip], limit=50)], limit=max)
| sources<=3
| sort(requests, order=ascending, limit=1000)"""], notes
        if slug == "07-http-post":
            return "Normalized HTTP or proxy telemetry", normalized_network("http.request.method=/^POST$/i", "url.domain"), notes
        if slug == "09-proxy-and-reverse-tunnel":
            return "Falcon process telemetry", native_process(PROCESS_PATTERNS[topic_slug]), notes

    if phase == "phase-09-exfiltration":
        if topic_slug in PROCESS_PATTERNS:
            return "Falcon process telemetry", native_process(PROCESS_PATTERNS[topic_slug]), notes
        if topic_slug in DNS_FILTERS:
            return "Falcon `DnsRequest` telemetry", dns(DNS_FILTERS[topic_slug]), notes
        if slug == "09-large-uploads":
            return "Normalized proxy, firewall, or flow telemetry", normalized_network('source.bytes>=100000000 | !cidr(destination.ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])'), notes

    if phase == "phase-10-malware-execution":
        if slug == "01-office-spawning-powershell":
            return "Falcon process telemetry", [r"""#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ParentBaseFileName=/^(winword|excel|powerpnt|outlook|onenote|mspub)\.exe$/i
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe$/i
| table([@timestamp, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData], limit=2000)"""], notes
        if slug == "02-office-spawning-cmd":
            return "Falcon process telemetry", [r"""#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ParentBaseFileName=/^(winword|excel|powerpnt|outlook|onenote|mspub)\.exe$/i
| ImageFileName=/\\cmd\.exe$/i
| table([@timestamp, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData], limit=2000)"""], notes
        if slug == "13-masquerading-system-binaries":
            return "Falcon process telemetry", [r"""#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ImageFileName=/\\(cmd|powershell|svchost|lsass|services|rundll32|regsvr32)\.exe$/i
| ImageFileName!=/^C:\\Windows\\(System32|SysWOW64)\\/i
| table([@timestamp, aid, UserSid, ParentBaseFileName, ImageFileName, OriginalFilename, CommandLine, SHA256HashData], limit=2000)"""], notes

    if phase == "phase-11-active-directory":
        code = slug.split("-", 1)[0]
        native = {
            "4624": r"""#event_simpleName=UserLogon event_platform=Win
| groupBy([UserName, LogonType, RemoteAddressIP4, aid], function=count(as=logons), limit=max)
| sort(logons, order=descending, limit=1000)""",
            "4625": r"""#event_simpleName=UserLogonFailed2 event_platform=Win
| groupBy([RemoteAddressIP4, UserName, LogonType, SubStatus], function=[count(as=failures), count(aid, distinct=true, as=endpoints)], limit=max)
| sort(failures, order=descending, limit=1000)""",
            "4688": r"""#event_simpleName=ProcessRollup2 event_platform=Win
| table([@timestamp, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, SHA256HashData], limit=5000)""",
            "4698": r"""#event_simpleName=ScheduledTaskRegistered
| table([@timestamp, aid, UserName, TaskName, TaskExecCommand, TaskExecArguments, TaskAuthor, TaskXml], limit=2000)""",
            "7045": r"""#event_simpleName=/^(ServiceStarted|ServiceRegistration)$/
| table([@timestamp, aid, UserName, ServiceName, ImagePath, CommandLine], limit=2000)""",
        }
        if code in native:
            return "Falcon endpoint telemetry", [native[code]], notes
        return "Windows Event Log normalized to CPS/ECS", [f"""event.code="{code}"
| table([@timestamp, host.name, user.name, source.ip, event.code, event.action, event.outcome, winlog.channel, winlog.event_data], limit=2000)
| groupBy([host.name, user.name, source.ip, event.outcome], function=count(as=events), limit=max)"""], notes

    if phase == "phase-12-ics-ot":
        selector, group = OT_FILTERS[topic_slug]
        return "Industrial network telemetry normalized to CPS/ECS; parser-specific OT fields may require adjustment", normalized_network(selector, group), notes + ["Join controller and engineering-workstation results to the authoritative OT asset inventory."]

    if phase == "phase-13-ioc-hunting":
        ioc_queries = {
            "01-ip": ip_pivot(),
            "02-domain": [r"""#event_simpleName=DnsRequest
| DomainName=?{domain=*}
| ioc:lookup(DomainName, type=domain, confidenceThreshold=unverified, strict=false)
| table([@timestamp, aid, ContextProcessId, DomainName, RequestType, ioc.malicious_confidence, ioc.labels], limit=5000)"""],
            "03-url": ["""url.full=?{url=*}
| table([@timestamp, source.ip, destination.ip, host.name, user.name, process.name, http.request.method, url.full, http.response.status_code, user_agent.original], limit=5000)"""],
            "04-hash": [r"""#event_simpleName=/^(ProcessRollup2|ImageHash|PeFileWritten|NewExecutableWritten|NewScriptWritten)$/
| SHA256HashData=?{sha256=*}
| table([@timestamp, #event_simpleName, aid, ContextProcessId, TargetProcessId, ImageFileName, TargetFileName, CommandLine, SHA256HashData], limit=5000)"""],
            "05-ja3": [r"""#event_simpleName=TlsClientHello
| JA3Hash=?{ja3=*}
| groupBy([JA3Hash, aid, ContextProcessId, RemoteAddressIP4, ServerName], function=count(as=handshakes), limit=max)"""],
            "06-user-agent": ["""user_agent.original=?{user_agent=*}
| groupBy([user_agent.original, source.ip, user.name, url.domain], function=[count(as=requests), collect(url.full, limit=50)], limit=max)"""],
            "07-yara": ["""rule.category=/^yara$/i OR yara.rule.name=*
| table([@timestamp, rule.name, yara.rule.name, host.name, user.name, process.name, file.path, file.hash.sha256, event.action], limit=5000)"""],
            "08-sigma": ["""rule.category=/^sigma$/i OR rule.name=?{sigma_rule=*}
| table([@timestamp, rule.name, rule.id, rule.category, event.dataset, host.name, user.name, process.name, process.command_line, source.ip, destination.ip], limit=5000)"""],
        }
        return "Falcon native or normalized IOC-bearing telemetry", ioc_queries[slug], notes + ["Replace wildcard parameter defaults with the exact case indicator."]

    if phase == "phase-14-pivot-cheat-sheets":
        if slug in {"found-suspicious-ip"}:
            return "Falcon endpoint telemetry; set the `ip` parameter", ip_pivot(), notes
        if slug == "found-beaconing":
            return "Falcon process and network telemetry; set `aid` and `process_id`", [r"""#event_simpleName=/^(NetworkConnectIP4|DnsRequest|TlsClientHello|ProcessRollup2)$/
| aid=?{aid=*}
| ContextProcessId=?{process_id=*} OR TargetProcessId=?{process_id=*}
| table([@timestamp, #event_simpleName, aid, ContextProcessId, TargetProcessId, ImageFileName, CommandLine, DomainName, RemoteAddressIP4, RemotePort, ServerName, JA3Hash], limit=5000)"""], notes
        if slug == "found-dns":
            return "Falcon DNS telemetry; set the `domain` parameter", dns("DomainName=?{domain=*}"), notes
        if slug in {"found-powershell", "found-repeated-powershell"}:
            queries = native_process(r"(\\powershell(_ise)?\.exe$|\\pwsh\.exe$)")
            if slug == "found-repeated-powershell":
                queries = [r"""#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe$/i
| groupBy([aid, UserSid, ParentBaseFileName, CommandLine, SHA256HashData], function=[count(as=executions), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)], limit=max)
| executions>=3
| sort(executions, order=descending, limit=1000)"""]
            return "Falcon process telemetry", queries, notes
        if slug == "found-rdp":
            return "Falcon RDP and logon telemetry", [r"""#event_simpleName=/^(UserLogon|UserLogonFailed2|ProcessExecOnRDPFile)$/ event_platform=Win
| (LogonType="10" OR #event_simpleName=ProcessExecOnRDPFile)
| UserName=?{user=*}
| table([@timestamp, #event_simpleName, aid, UserName, RemoteAddressIP4, ContextProcessId, ImageFileName, CommandLine, TargetFileName], limit=5000)"""], notes
        if slug == "found-smb":
            return queries_for("phase-06-lateral-movement", "01-smb")
        if slug == "found-winrm":
            return "Falcon process and network telemetry", [r"""#event_simpleName=/^(NetworkConnectIP4|UserLogon|ProcessRollup2)$/ event_platform=Win
| (RemotePort=/^(5985|5986)$/ OR ImageFileName=/\\(wsmprovhost|winrs|powershell|pwsh)\.exe$/i)
| table([@timestamp, #event_simpleName, aid, UserName, UserSid, RemoteAddressIP4, RemotePort, ParentBaseFileName, ImageFileName, CommandLine], limit=5000)"""], notes
        if slug == "found-telemetry-gap":
            return "Falcon sensor health telemetry", [r"""#event_simpleName=/^(AgentOnline|SensorHeartbeat)$/
| groupBy(aid, function=[max(@timestamp, as=lastSeen), collect([ComputerName, AgentVersion], limit=5)], limit=max)
| sort(lastSeen, order=ascending, limit=1000)"""], notes

    raise KeyError(f"No query generator for {phase}/{slug}")


def build_file(source_file: Path) -> str:
    relative = source_file.relative_to(SOURCE)
    phase, filename = relative.parts
    slug = source_file.stem
    source_title = source_file.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ").strip()
    data_source, queries, notes = queries_for(phase, slug)
    topic = humanize(slug)
    purpose = PHASE_PURPOSE[phase]
    blocks = "\n\n".join(f"```cql\n{query.strip()}\n```" for query in queries)
    note_lines = "\n".join(f"- {note}" for note in notes)
    return fr"""# {source_title} - CrowdStrike Next-Gen SIEM

## What this does

Hunts for **{topic}** to {purpose}. The result keeps the endpoint, account, process, network peer, and time fields needed to validate the behavior and continue scoping.

## Required data

{data_source}. Native Falcon queries use `#event_simpleName`; third-party queries expect CrowdStrike Parsing Standard/ECS-style normalized fields.

## CrowdStrike Query Language

{blocks}

## Tuning and investigation notes

{note_lines}
"""


def main() -> None:
    source_files = sorted(SOURCE.glob("phase-*/*.md"))
    if len(source_files) != 158:
        raise RuntimeError(f"Expected 158 Security Onion files, found {len(source_files)}")
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for source_file in source_files:
        destination = DESTINATION / source_file.relative_to(SOURCE)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(build_file(source_file), encoding="utf-8", newline="\n")

    readme = r"""# CrowdStrike Next-Gen SIEM Query Guide

This directory mirrors the 14-phase hunt structure in `queries/security-onion`, but the queries use CrowdStrike Query Language (CQL) for Falcon Next-Gen SIEM.

## Coverage model

- Native Falcon endpoint hunts use tagged event names such as `#event_simpleName=ProcessRollup2`, `NetworkConnectIP4`, `DnsRequest`, and `UserLogon`.
- Network, firewall, proxy, email, identity, Windows Event Log, and OT hunts use CrowdStrike Parsing Standard/ECS-style normalized fields and require the corresponding data source and parser.
- Field availability varies by sensor version, operating system, parser, and license. Inspect a representative raw event and adjust the dataset selector or field alias before operationalizing a query.
- CQL parameters use the `?{name=*}` form. Replace the wildcard default with the case value before running a pivot.
- Use a bounded absolute time range. Thresholds are starting points that must be baselined for the environment.

## Authoritative references

- [CrowdStrike Query Language syntax](https://library.humio.com/data-analysis/syntax.html)
- [CrowdStrike Falcon LogScale tutorial query examples](https://library.humio.com/integrations/integrations-crowdstrike-fltr-tutorial-crowdstrike-fltr-tutorial.html)
- [CrowdStrike FLTR core dashboard queries and Falcon event fields](https://library.humio.com/integrations/integrations-crowdstrike-fltr-core-crowdstrike-fltr-core.html)
- [CrowdStrike community CQL content](https://github.com/CrowdStrike/logscale-community-content)
"""
    (DESTINATION / "README.md").write_text(readme, encoding="utf-8", newline="\n")
    print(f"Generated {len(source_files)} CrowdStrike query guides in {DESTINATION}")


if __name__ == "__main__":
    main()

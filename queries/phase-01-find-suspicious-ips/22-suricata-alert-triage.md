# Suricata Alert Triage

```
event.dataset:suricata.alert | groupby rule.name
```

```
event.dataset:suricata.alert AND event.severity_label:high | groupby rule.name source.ip destination.ip network.direction
```

```
event.dataset:suricata.alert AND event.severity:1 | groupby rule.name source.ip destination.ip network.direction
```

```
event.dataset:suricata.alert AND (rule.name:(*MALWARE* OR *C2* OR *CNC* OR *Metasploit* OR *Meterpreter* OR *SCAN* OR *SSH* OR *PE* OR *DLL*) OR rule.category:("A Network Trojan was detected" OR "Executable code was detected" OR "Attempted Information Leak")) | groupby source.ip destination.ip rule.name network.direction
```

```
event.dataset:suricata.alert AND source.ip:<IP> | groupby destination.ip destination.port rule.name network.direction
```

```
network.community_id:<COMMUNITY_ID>
```

Treat breadth and sequence as evidence: the same high-value alert from one
source to several destinations, or a download alert followed by a C2/stager
alert, warrants rapid scoping. Confirm handler/victim roles with direction and
PCAP/community ID, never port numbers alone.
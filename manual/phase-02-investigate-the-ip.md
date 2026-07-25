# Phase 2 — Investigate the Suspicious IP

Use Phase 2 to turn one IP into an evidence-backed timeline. Record the lead, exact time range, traffic direction, and whether the address is internal or external. Begin with the broad pivot and group by host, port, protocol, connection state, and time. Then examine DNS, HTTP, TLS, SMB/RDP/WinRM, Suricata, and endpoint process evidence.

DNS may reveal the domain behind an address; HTTP and TLS provide request, SNI, certificate, and fingerprint context; endpoint telemetry identifies process, parent, user, and command line. Use `network.community_id` to connect Suricata findings with the underlying flow. Missing results may reflect encryption, NAT, proxying, or sensor placement, so record unavailable telemetry.

Corroborate independent signals. A rare destination combined with a new domain, unusual TLS, PowerShell, and regular timing is much stronger than any one signal. Search around the first connection for entry, execution, discovery, persistence, movement, and transfer activity.

**Next pivots:** Phases 3, 6, 8, 9, and 10. **Success:** explain who communicated, when, how, and why the activity is benign or requires escalation.

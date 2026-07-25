# Phase 13 — IOC Hunting

Phase 13 is the workflow for scoping known IPs, domains, URLs, hashes, fingerprints, and detections. Start with a clear lead, an absolute time range, and the asset and identity context needed to distinguish legitimate operations from suspicious behavior. Run the focused query files one at a time, record their results, and pivot on the resulting host, account, process, IP, domain, hash, and timestamp.

Treat a single match as a lead rather than proof. Establish the actor, affected system, parent process or source, target, outcome, and nearby activity. Compare against expected business role, approved tools, change windows, and historical baseline. Combine endpoint, network, identity, and alert evidence whenever possible, and explicitly record telemetry that is unavailable or ambiguous.

Preserve relevant event metadata and artifacts before containment or remediation. Scope the same indicator or behavior across peers, then follow the result into the related behavior phases. For OT work, coordinate first with operational owners; for identity or data findings, coordinate with the relevant response owners.

**Success condition:** The finding has a documented evidence chain, a benign explanation or escalation rationale, and a clear next investigative action.

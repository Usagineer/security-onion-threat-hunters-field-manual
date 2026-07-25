# Phase 12 - ICS / OT

 **Analyst question:** What operational function occurred, is it authorized, and what is the potential safety or production impact?

## What this phase is for

Safely investigate industrial protocol traffic, engineering activity, controllers, and IT-to-OT paths.

## What makes a result meaningful

OT context and owner validation are mandatory; avoid active probing or disruptive containment without authority.
A useful finding usually has a sequence: an initiating event, an observable action, supporting context, and an affected asset or account. Record both confirming evidence and evidence that weakens the hypothesis; this makes handoffs and containment decisions defensible.

## Why use each query?

Choose the query that matches the behavior in the lead. Each result should give you a focused valuesuch as a host, account, IP, process, domain, or timestampto pivot into the next query or phase.

### [Modbus](../queries/phase-12-ics-ot/01-modbus.md)

#### Why Hunt This

Hunt for **Modbus** because Modbus function codes reveal industrial reads, writes, diagnostics, and control actions. This query searches **event.dataset:zeek.modbus, event.dataset:zeek.conn, ports 502** and organizes matches by **source.ip destination.ip modbus.function; source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can issue weakly protected commands to coils and registers. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which devices, unit IDs, and functions respond. From **Modbus**, the likely next move is to alter state or target the process more precisely. Analyst pivot: **source.ip destination.ip modbus.function; source.ip destination.ip** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [Ethernet Ip](../queries/phase-12-ics-ot/02-ethernet-ip.md)

#### Why Hunt This

Hunt for **Ethernet Ip** because EtherNet/IP sessions identify routable industrial communications. This query searches **event.dataset:zeek.conn, event.dataset:zeek.enip, ports 44818** and organizes matches by **source.ip destination.ip; source.ip destination.ip enip.command**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can enumerate or interact with industrial devices across zones. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which devices and paths are reachable. From **Ethernet Ip**, the likely next move is to issue CIP requests or target controllers. Analyst pivot: **source.ip destination.ip; source.ip destination.ip enip.command** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [Cip](../queries/phase-12-ics-ot/03-cip.md)

#### Why Hunt This

Hunt for **Cip** because CIP services and objects reveal controller reads, writes, and identity queries. This query searches **event.dataset:zeek.cip** and organizes matches by **source.ip destination.ip cip.service; source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can enumerate or modify controller objects. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which classes, instances, and services respond. From **Cip**, the likely next move is to move from discovery to programming. Analyst pivot: **source.ip destination.ip cip.service; source.ip destination.ip** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [Dnp3](../queries/phase-12-ics-ot/04-dnp3.md)

#### Why Hunt This

Hunt for **Dnp3** because DNP3 functions reveal master/outstation telemetry and control. This query searches **event.dataset:zeek.dnp3, event.dataset:zeek.conn, ports 20000** and organizes matches by **source.ip destination.ip dnp3.function; source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can misuse a master role to issue control operations. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which outstations and points accept commands. From **Dnp3**, the likely next move is to operate points or disrupt polling. Analyst pivot: **source.ip destination.ip dnp3.function; source.ip destination.ip** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [Bacnet](../queries/phase-12-ics-ot/05-bacnet.md)

#### Why Hunt This

Hunt for **Bacnet** because BACnet services reveal building-automation discovery and property access. This query searches **event.dataset:zeek.conn, event.dataset:zeek.bacnet, ports 47808** and organizes matches by **source.ip destination.ip; source.ip destination.ip bacnet.service**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can enumerate devices and change HVAC, access, alarm, or schedule properties. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which devices and objects allow writes. From **Bacnet**, the likely next move is to alter setpoints or disrupt building operations. Analyst pivot: **source.ip destination.ip; source.ip destination.ip bacnet.service** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [Opc Ua](../queries/phase-12-ics-ot/06-opc-ua.md)

#### Why Hunt This

Hunt for **Opc Ua** because OPC UA sessions reveal endpoint, node, method, and security-mode activity. This query searches **event.dataset:zeek.conn, ports 4840** and organizes matches by **source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can browse nodes, read data, invoke methods, or write values. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which credentials, endpoints, and nodes are available. From **Opc Ua**, the likely next move is to move to process manipulation. Analyst pivot: **source.ip destination.ip** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [S7](../queries/phase-12-ics-ot/07-s7.md)

#### Why Hunt This

Hunt for **S7** because S7 sessions reveal Siemens controller and engineering activity. This query searches **event.dataset:zeek.conn, event.dataset:zeek.s7comm, ports 102** and organizes matches by **source.ip destination.ip; source.ip destination.ip s7comm.function**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can query or manipulate PLC state and program functions. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which PLCs and programming operations respond. From **S7**, the likely next move is to change blocks, logic, or operating state. Analyst pivot: **source.ip destination.ip; source.ip destination.ip s7comm.function** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [Engineering Workstations](../queries/phase-12-ics-ot/08-engineering-workstations.md)

#### Why Hunt This

Hunt for **Engineering Workstations** because engineering-workstation activity identifies privileged OT configuration paths. This query searches **event.dataset:zeek.conn, ports 102/502/44818/20000/4840** and organizes matches by **source.ip destination.ip destination.port**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can compromise trusted engineering software and credentials. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which projects, tools, and controller paths are available. From **Engineering Workstations**, the likely next move is to program PLCs or pivot deeper into OT. Analyst pivot: **source.ip destination.ip destination.port** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [Plc Programming](../queries/phase-12-ics-ot/09-plc-programming.md)

#### Why Hunt This

Hunt for **Plc Programming** because program upload, download, and write activity can expose controller changes. This query searches **event.dataset:zeek.s7comm, event.dataset:zeek.cip, event.dataset:zeek.modbus** and organizes matches by **source.ip destination.ip**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can modify logic, firmware, setpoints, or operating state. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which controller accepts programming. From **Plc Programming**, the likely next move is to deploy logic changes or inhibit operations. Analyst pivot: **source.ip destination.ip** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [Unauthorized Controllers](../queries/phase-12-ics-ot/10-unauthorized-controllers.md)

#### Why Hunt This

Hunt for **Unauthorized Controllers** because new controller identities can expose rogue or impersonated devices. This query searches **event.dataset:zeek.conn, ports 102/502/44818/20000/4840** and organizes matches by **source.ip; source.ip destination.ip destination.port**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can introduce or impersonate a controller. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which systems trust the unauthorized device. From **Unauthorized Controllers**, the likely next move is to redirect traffic or establish a control point. Analyst pivot: **source.ip; source.ip destination.ip destination.port** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

### [It Ot Boundary And Hmi Impact](../queries/phase-12-ics-ot/11-it-ot-boundary-and-hmi-impact.md)

#### Why Hunt This

Hunt for **It Ot Boundary And Hmi Impact** because cross-zone and HMI activity identifies movement toward operator interfaces. This query searches **event.dataset:zeek.conn, ports 102/502/20000/44818/4840** and organizes matches by **source.ip destination.ip destination.port; destination.ip destination.port**, exposing the concrete artifacts needed to prove or rule out this behavior.

#### Attack Use

An adversary can cross the IT/OT boundary and misuse HMI access. Review the result in the context of the asset owner and expected workflow; the protocol or tool alone is not proof of malicious intent.

#### Attacker Pivot

By this point, the attacker may have learned which accounts and services reach operations. From **It Ot Boundary And Hmi Impact**, the likely next move is to manipulate displays, setpoints, services, or controllers. Analyst pivot: **source.ip destination.ip destination.port; destination.ip destination.port** into **owner-validated engineering and controller activity**, then verify the sequence with an independent telemetry source.

## Pivots and evidence preservation

Coordinate with OT owners, then use Phases 6, 8, and 10 only when safe and relevant.
Before deleting artifacts, disabling an account, or blocking traffic, preserve the relevant raw events, process or file metadata, timestamps, identifiers, and configuration. Include data that establishes direction and outcome, not only the alert that opened the case. If telemetry is absent, record the gap and use another data source rather than assuming no activity occurred.

## Common false positives

Approved administration, software deployment, monitoring, backup, security products, and maintenance can resemble attacker behavior. Verify the operator, signer, path, parent process, target population, and change record. A known tool used from an unexpected location, by an unexpected account, or in an unexpected sequence still needs investigation.

## Analyst handoff checklist

- [ ] Incident time range and timezone recorded.
- [ ] Original lead and each pivot value recorded.
- [ ] Source, target, account, process, and outcome identified where telemetry allows.
- [ ] Benign explanation validated or escalation rationale documented.
- [ ] Related hosts, accounts, indicators, and evidence-preservation needs scoped.

## Completion criteria

What operational function occurred, is it authorized, and what is the potential safety or production impact? If the answer remains unclear, state what telemetry or owner validation is missing and continue from the most relevant next phase.

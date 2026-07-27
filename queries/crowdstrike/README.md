# CrowdStrike Next-Gen SIEM Query Guide

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

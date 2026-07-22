# Automation — run the manual's queries against Security Onion

`so_hunt.py` translates the Field Manual query files into Elasticsearch searches
and runs them against your Security Onion cluster. Use it to sweep a whole phase
in one command, schedule recurring hunts, or pivot fast on an IP.

> **Authorized defensive use only.** Run this against Security Onion instances you
> own or operate. It is read-only (it only issues `_search`), but treat the
> credentials it uses like any other privileged access.

## How it works

Each query in the manual is Security Onion **Hunt** syntax:

```
event.dataset:zeek.conn AND NOT destination.ip:"10.0.0.0/8" | groupby destination.ip
```

`so_hunt.py` splits that on the pipe:

| Hunt syntax | Elasticsearch |
|---|---|
| text left of `|` | `query_string` query |
| `| groupby a` | `terms` aggregation on `a` (bucketed counts) |
| `| groupby a b` | `multi_terms` aggregation on `a`,`b` |
| no pipe | plain search, newest matching docs first |

`--order asc` (or `--rare`) sorts buckets **rarest-first** — the Phase 1 move.

## Install

```
pip install -r automation/requirements.txt
cp automation/.env.example automation/.env    # then edit .env
```

Only dependency is `requests`. Python 3.8+.

## Connect to Elasticsearch

Run `so_hunt.py` **on the SO manager** (simplest — `https://localhost:9200`), or
from a host you've allowed to reach ES.

Create a read-only ES user for it (on the manager):

```
sudo so-user add hunter        # follow prompts; or use Kibana > Stack Management > Users
```

…and grant it a role with `read` + `view_index_metadata` on `logs-*` / `so-*`.
An **API key** (Kibana → Stack Management → API Keys) works too and is preferable
for scheduled jobs — put it in `SO_ES_API_KEY`.

Put the endpoint, index pattern, and credentials in `automation/.env`
(see `.env.example`). Confirm connectivity:

```
python automation/so_hunt.py --query "*" --last 15m --size 1
```

## Usage

Run one file (every query block in it):

```
python automation/so_hunt.py --file queries/phase-01-find-suspicious-ips/01-rare-destination-ip.md --rare --last 7d
```

Sweep an entire phase:

```
python automation/so_hunt.py --phase queries/phase-01-find-suspicious-ips --last 24h
```

Run a literal query:

```
python automation/so_hunt.py --query 'event.module:suricata AND event.severity_label:high | groupby rule.name source.ip destination.ip'
```

Fill in placeholders (queries with unresolved `<...>` are skipped unless you
provide them):

```
python automation/so_hunt.py --file queries/phase-02-investigate-the-ip/00-everything.md --var IP=10.0.1.2
```

Save results, or inspect the translation without running it:

```
python automation/so_hunt.py --phase queries/phase-01-find-suspicious-ips --csv hunt.csv
python automation/so_hunt.py --file queries/.../10-beaconing.md --dry-run
```

### Useful flags

| Flag | Meaning |
|---|---|
| `--last 24h` / `7d` / `30d` | relative time window (default 24h) |
| `--from` / `--to` | absolute ISO time range (overrides `--last`) |
| `--rare` / `--order asc` | rarest buckets first |
| `--size N` | number of buckets / hits (default 25) |
| `--var KEY=VALUE` | substitute `<KEY>`; repeatable |
| `--allow-placeholders` | run even with unresolved `<...>` |
| `--dry-run` | print the ES query body, don't execute |
| `--csv FILE` / `--json` | output formats |

## Scheduling a recurring hunt

**Linux (cron)** — daily 7-day rare-destination sweep to CSV:

```
0 7 * * *  cd /opt/manual && python3 automation/so_hunt.py \
  --file queries/phase-01-find-suspicious-ips/01-rare-destination-ip.md \
  --rare --last 7d --csv /var/log/hunts/rare-dest-$(date +\%F).csv
```

**Windows (Task Scheduler)** — run `so_hunt.py` with the same args on a trigger.

## Caveats

- **Field types.** Aggregations need aggregatable (keyword/ip/numeric) fields.
  Most ECS fields (`destination.ip`, `rule.name`, `dns.question.name`) work as-is;
  if you get an aggregation error on a text field, use its `.keyword` variant.
- **Index pattern & version.** SO 2.4 = `logs-*`; older = `so-*`; distributed may
  need `*:so-*`. Set `SO_ES_INDEX` to match your deployment.
- **Endpoint dataset names** (`event.module:endpoint`, `process.*`) depend on your
  telemetry (Elastic Defend/Endgame here) — same caveat as the manual itself.
- Placeholder tokens (`<IP>`, `<HOST>`, ranges) must be supplied with `--var` or
  the query is skipped by design.

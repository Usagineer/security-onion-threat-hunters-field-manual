#!/usr/bin/env python3
"""
so_hunt.py — run Field Manual queries against Security Onion's Elasticsearch.

The manual's query files are Security Onion "Hunt" syntax:  a Lucene query,
optionally followed by ``| groupby field [field ...]`` (a UI-only aggregation).
This tool translates that into an Elasticsearch ``_search``:

    left of the pipe  -> query_string query
    | groupby a b     -> terms / multi_terms aggregation (bucketed counts)
    no pipe           -> plain search returning the newest matching documents

It can run a single literal query, every query in one ``.md`` file, or every
file in a whole phase directory.

Read automation/README.md first — you need Elasticsearch credentials and
network reachability to the SO manager (default https://localhost:9200).

For AUTHORIZED defensive threat hunting on systems you own/operate only.
"""
import argparse
import csv
import glob
import json
import os
import re
import sys


def _import_requests():
    """Imported lazily so --dry-run works without the dependency installed."""
    try:
        import requests
    except ImportError:
        sys.exit("Missing dependency: pip install -r automation/requirements.txt")
    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    except Exception:
        pass
    return requests

PLACEHOLDER_RE = re.compile(r"<[A-Za-z0-9_./:-]+>")
CODE_BLOCK_RE = re.compile(r"```[a-zA-Z0-9]*\n(.*?)\n```", re.DOTALL)


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def load_dotenv():
    """Load KEY=VALUE lines from a .env in cwd or next to this script."""
    for path in (".env", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


class Config:
    def __init__(self, args):
        self.url = (args.es_url or os.environ.get("SO_ES_URL") or "https://localhost:9200").rstrip("/")
        self.index = args.index or os.environ.get("SO_ES_INDEX") or "logs-*,so-*"
        self.user = args.es_user or os.environ.get("SO_ES_USER")
        self.password = args.es_pass or os.environ.get("SO_ES_PASS")
        self.api_key = args.api_key or os.environ.get("SO_ES_API_KEY")
        self.verify = args.verify
        self.timeout = args.timeout

    def auth_headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"ApiKey {self.api_key}"
        return h

    def basic_auth(self):
        if self.api_key:
            return None
        if self.user and self.password:
            return (self.user, self.password)
        return None


# --------------------------------------------------------------------------- #
# Query parsing / translation
# --------------------------------------------------------------------------- #
def parse_query_file(path):
    """Return (title, [query, ...]) from a manual .md query file."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    title = os.path.basename(path)
    for line in text.splitlines():
        if line.strip():
            title = line.strip().lstrip("#").strip() or title
            break
    queries = [b.strip() for b in CODE_BLOCK_RE.findall(text) if b.strip()]
    # Fall back to treating blank-line-separated blocks as queries (plain .txt)
    if not queries:
        body = "\n".join(text.splitlines()[1:])
        queries = [b.strip() for b in body.split("\n\n") if b.strip()]
    return title, queries


def split_groupby(query):
    """('lucene', ['field', ...] | None) from a Hunt query string."""
    if "|" not in query:
        return query.strip(), None
    left, _, right = query.partition("|")
    right = right.strip()
    if not right.lower().startswith("groupby"):
        # Unsupported pipe (e.g. | sankey). Ignore the pipe, search the left.
        return left.strip(), None
    tokens = right.split()[1:]  # drop the word "groupby"
    fields = [t for t in tokens if not t.startswith("-")]
    return left.strip(), (fields or None)


def substitute_vars(query, variables):
    for k, v in variables.items():
        query = query.replace(f"<{k}>", v)
    return query


def build_body(lucene, fields, time_from, time_to, size, order):
    must = []
    if lucene:
        must.append({"query_string": {"query": lucene, "analyze_wildcard": True}})
    rng = {}
    if time_from:
        rng["gte"] = time_from
    if time_to:
        rng["lte"] = time_to
    filt = [{"range": {"@timestamp": rng}}] if rng else []
    query = {"bool": {"must": must or [{"match_all": {}}], "filter": filt}}

    if fields:
        if len(fields) == 1:
            agg = {"terms": {"field": fields[0], "size": size, "order": {"_count": order}}}
        else:
            agg = {
                "multi_terms": {
                    "terms": [{"field": f} for f in fields],
                    "size": size,
                    "order": {"_count": order},
                }
            }
        return {"size": 0, "query": query, "aggs": {"groupby": agg}}, True

    # plain search: newest documents first, a useful default column set
    return {
        "size": size,
        "query": query,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": [
            "@timestamp", "event.dataset", "event.module", "source.ip",
            "source.port", "destination.ip", "destination.port", "rule.name",
            "rule.category", "dns.question.name", "url.domain",
            "process.name", "process.command_line", "host.name",
        ],
    }, False


# --------------------------------------------------------------------------- #
# Execution / output
# --------------------------------------------------------------------------- #
def run_search(cfg, body):
    requests = _import_requests()
    url = f"{cfg.url}/{cfg.index}/_search?ignore_unavailable=true&allow_no_indices=true"
    resp = requests.post(
        url,
        headers=cfg.auth_headers(),
        auth=cfg.basic_auth(),
        data=json.dumps(body),
        verify=cfg.verify,
        timeout=cfg.timeout,
    )
    if resp.status_code == 401:
        raise SystemExit("401 Unauthorized — check SO_ES_USER/SO_ES_PASS or SO_ES_API_KEY.")
    if resp.status_code >= 400:
        raise RuntimeError(f"ES {resp.status_code}: {resp.text[:400]}")
    return resp.json()


def rows_from_response(data, fields, is_agg):
    """Normalize either aggregation buckets or hits into (columns, rows)."""
    if is_agg:
        buckets = data.get("aggregations", {}).get("groupby", {}).get("buckets", [])
        cols = fields + ["count"]
        rows = []
        for b in buckets:
            key = b["key"]
            key = key if isinstance(key, list) else [key]
            rows.append([str(k) for k in key] + [b["doc_count"]])
        return cols, rows
    hits = data.get("hits", {}).get("hits", [])
    cols = ["@timestamp", "event.dataset", "source.ip", "destination.ip",
            "destination.port", "rule.name"]
    rows = []
    for h in hits:
        src = h.get("_source", {})
        rows.append([dig(src, c) for c in cols])
    return cols, rows


def dig(src, dotted):
    cur = src
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return ""
    if isinstance(cur, list):
        return ", ".join(str(x) for x in cur)
    return "" if cur is None else str(cur)


def print_table(cols, rows):
    if not rows:
        print("  (no results)")
        return
    widths = [len(c) for c in cols]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  ".join(c.ljust(widths[i]) for i, c in enumerate(cols))
    print("  " + line)
    print("  " + "  ".join("-" * widths[i] for i in range(len(cols))))
    for r in rows:
        print("  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)))


def write_csv(out, cols, rows):
    with open(out, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(rows)


# --------------------------------------------------------------------------- #
# Drivers
# --------------------------------------------------------------------------- #
def gather_targets(args):
    """Return a list of (label, query) to run."""
    targets = []
    if args.query:
        targets.append(("(inline query)", args.query))
    if args.file:
        title, queries = parse_query_file(args.file)
        for q in queries:
            targets.append((title, q))
    if args.phase:
        files = sorted(glob.glob(os.path.join(args.phase, "*.md")) +
                       glob.glob(os.path.join(args.phase, "*.txt")))
        for path in files:
            title, queries = parse_query_file(path)
            for q in queries:
                targets.append((f"{os.path.basename(path)} :: {title}", q))
    return targets


def main():
    load_dotenv()
    ap = argparse.ArgumentParser(
        description="Run Security Onion Field Manual queries against Elasticsearch.")
    src = ap.add_argument_group("what to run (pick one)")
    src.add_argument("--query", help="a single literal Hunt query")
    src.add_argument("--file", help="a query .md file (runs every code block)")
    src.add_argument("--phase", help="a phase directory (runs every file in it)")

    ap.add_argument("--es-url", help="default https://localhost:9200 or $SO_ES_URL")
    ap.add_argument("--index", help='index pattern (default "logs-*,so-*")')
    ap.add_argument("--es-user", help="$SO_ES_USER")
    ap.add_argument("--es-pass", help="$SO_ES_PASS")
    ap.add_argument("--api-key", help="$SO_ES_API_KEY (alternative to user/pass)")
    ap.add_argument("--verify", action="store_true",
                    help="verify TLS cert (default off — SO uses self-signed)")
    ap.add_argument("--timeout", type=int, default=60)

    ap.add_argument("--last", default="24h",
                    help='relative window, e.g. 24h, 7d, 30d (default 24h)')
    ap.add_argument("--from", dest="time_from", help="absolute ISO start (overrides --last)")
    ap.add_argument("--to", dest="time_to", help="absolute ISO end")
    ap.add_argument("--size", type=int, default=25, help="buckets / hits to return")
    ap.add_argument("--order", choices=["asc", "desc"], default="desc",
                    help="groupby count order (asc = rarest first)")
    ap.add_argument("--rare", action="store_true", help="shortcut for --order asc")
    ap.add_argument("--var", action="append", default=[], metavar="KEY=VALUE",
                    help="substitute <KEY> in queries; repeatable")
    ap.add_argument("--allow-placeholders", action="store_true",
                    help="run queries even if <PLACEHOLDERS> remain (default: skip them)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the translated ES query body, do not execute")
    ap.add_argument("--csv", help="append all results to this CSV file")
    ap.add_argument("--json", action="store_true", help="print raw ES JSON responses")
    args = ap.parse_args()

    if not (args.query or args.file or args.phase):
        ap.error("pick one of --query, --file, or --phase")

    variables = {}
    for pair in args.var:
        if "=" not in pair:
            ap.error(f"--var expects KEY=VALUE, got: {pair}")
        k, v = pair.split("=", 1)
        variables[k.strip()] = v.strip()

    order = "asc" if args.rare else args.order
    time_from = args.time_from or f"now-{args.last}"
    time_to = args.time_to

    cfg = Config(args)
    if not args.dry_run and not cfg.basic_auth() and not cfg.api_key:
        raise SystemExit("No credentials. Set SO_ES_USER/SO_ES_PASS or SO_ES_API_KEY "
                         "(see automation/README.md).")

    targets = gather_targets(args)
    ran = skipped = 0
    for label, raw in targets:
        query = substitute_vars(raw, variables)
        leftover = PLACEHOLDER_RE.findall(split_groupby(query)[0]) + \
            [f"<{f}>" for f in (split_groupby(query)[1] or []) if PLACEHOLDER_RE.match(f)]
        if PLACEHOLDER_RE.search(query) and not args.allow_placeholders:
            print(f"\n# {label}")
            print(f"  ! skipped (unresolved placeholder). Provide it, e.g. --var "
                  f"{PLACEHOLDER_RE.search(query).group().strip('<>')}=... : {query}")
            skipped += 1
            continue

        lucene, fields = split_groupby(query)
        body, is_agg = build_body(lucene, fields, time_from, time_to, args.size, order)

        print(f"\n# {label}")
        print(f"  query : {query}")
        if args.dry_run:
            print(json.dumps(body, indent=2))
            ran += 1
            continue
        try:
            data = run_search(cfg, body)
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR: {e}")
            if fields:
                print("  hint: if this is an aggregation error, the field may be text; "
                      "try the .keyword variant.")
            continue
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            cols, rows = rows_from_response(data, fields or [], is_agg)
            total = data.get("hits", {}).get("total", {})
            total = total.get("value") if isinstance(total, dict) else total
            print(f"  total matches: {total}")
            print_table(cols, rows)
            if args.csv:
                write_csv(args.csv, cols, rows)
        ran += 1

    print(f"\n[done] {ran} run, {skipped} skipped, {len(targets)} total")


if __name__ == "__main__":
    main()

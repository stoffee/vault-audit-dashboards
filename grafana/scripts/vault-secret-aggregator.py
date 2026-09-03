#!/usr/bin/env python3
"""Vault secret-hygiene aggregator: folds the audit stream into per-secret state.

Folds a Vault audit-log stream into a per-secret state table
    (namespace, path) -> last_read, last_write, reads, writes
and publishes two low-cardinality outputs:

  * Prometheus: age-bucket COUNTS (a handful of series, never per-secret).
  * Loki: one findings line per flagged secret, stamped NOW.

Why this shape (see docs/how-it-works.md):
  Secret path can never be a Prometheus label or a Loki stream label. A large estate
  has hundreds of thousands of KV v2 secrets; that many active series kills both. The
  fold happens here, in process, and only the aggregate crosses the wire. Per-secret
  detail travels as log LINES (cheap) rather than as labels (ruinous).

Why the findings are stamped now, not at the secret's last-read time:
  A finding is an observation made today about history. Stamping it "now" also means
  it sails past Loki's reject_old_samples window, which would otherwise refuse an
  18-month-old timestamp outright.

The state table is the 18-month answer. In production it MUST be checkpointed to
disk/DB; losing it resets the clock. --state-file does that here.

Input:
  --audit FILE.jsonl      Vault audit device output, one JSON object per line.
                          Pass "-" to read from stdin, for a device that writes to
                          stdout/pod logs rather than a file on disk.
  --inventory FILE.csv    Baseline path list. REQUIRED to see "never read" secrets:
                          a secret nobody reads emits no audit event at all, so it
                          exists only here. Without it the most important number is
                          silently missing.
  --mounts LIST           Comma-separated mount_types to fold. Default "kv" only,
                          which preserves this tool's original behavior. The /data/
                          path requirement is a KV v2 artifact and is only enforced
                          for the kv mount type; other engines fold every path.

Usage:
  ./vault-secret-aggregator.py --audit sample.jsonl --inventory inv.csv --print
  ./vault-secret-aggregator.py --audit sample.jsonl --inventory inv.csv \
      --pushgateway http://<pushgateway-host>:9091 --loki http://<loki-host>:3100
  kubectl logs -n vault sts/vault -c vault --since=24h | \
      ./vault-secret-aggregator.py --audit - --inventory inv.csv --print
"""

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict

DAY = 86400
BUCKETS = [30, 90, 180, 365, 540]
JOB = "vault-secret-hygiene"

# KV v2 API prefixes. Only /data/ is *use*; metadata/ and subkeys/ are browsing
# (the UI, `vault kv metadata get`) and must not count as a read, or every secret
# anyone has ever looked at looks active.
DATA_PREFIX = "/data/"
BROWSE_PREFIXES = ("/metadata/", "/subkeys/")


# ---------------------------------------------------------------- fold ----
def _audit_lines(audit_path):
    """Yield lines from a file, or from stdin when audit_path is "-".

    A device that writes to stdout (captured as pod logs, piped in) has no file to
    open. Closing stdin at the end is harmless in a one-shot CLI.
    """
    if audit_path == "-":
        yield from sys.stdin
    else:
        with open(audit_path) as fh:
            yield from fh


def resolve_namespace(req):
    """Prefer namespace.path, fall back to namespace.id, then "".

    Open-source Vault audit devices verified emitting ONLY namespace.id (namespaces
    are an Enterprise feature there in the first place, so path is absent by
    definition). Whether Enterprise emits path alongside id is UNPROVEN here; if it
    does not, every tenant folds into one bucket, silently, which is the worst
    failure mode for a namespace-per-tenant estate. Path is preferred when present
    so existing behavior for anyone already getting `path` is unchanged.

    Root is normalized to "": Vault's root namespace has the fixed id "root" (not
    an empty id), so a naive fallback bakes the literal text "root" onto the front
    of every key built as ns + path, producing paths like "rootkv/data/app/db"
    instead of "kv/data/app/db". Path-based root already yields "" here (an empty
    path field, not the string "root"), so without this the two ways of expressing
    "no namespace" would build different, inconsistent keys for the same secret.
    """
    nsobj = req.get("namespace") or {}
    ns = nsobj.get("path") or nsobj.get("id") or ""
    return "" if ns == "root" else ns


def fold(audit_path, inventory_path=None, mounts=("kv",)):
    """Stream the audit log into a per-secret state table.

    mounts: which request.mount_type values to fold. The /data/ path requirement
    is a KV v2 API artifact and is enforced ONLY for mount_type "kv"; every other
    engine in `mounts` folds on path alone. Events whose mount_type is not in
    `mounts` are counted in `skipped_by_mount` but otherwise ignored, so a caller
    can report what was left out rather than silently dropping it.
    """
    last_read, last_write = {}, {}
    reads, writes = defaultdict(int), defaultdict(int)
    denials = defaultdict(int)          # (namespace, path, who) -> count
    denial_last_seen = {}
    namespaces = {}
    seen, scanned, matched = set(), 0, 0
    skipped_by_mount = defaultdict(int)
    mounts = set(mounts)

    for line in _audit_lines(audit_path):
        scanned += 1
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") != "response":
            continue
        req = ev.get("request") or {}
        mount_type = req.get("mount_type")
        if mount_type not in mounts:
            skipped_by_mount[mount_type or "(none)"] += 1
            continue
        path = req.get("path", "")
        if mount_type == "kv" and DATA_PREFIX not in path:
            continue                       # browsing or a directory list
        ns = resolve_namespace(req)
        key = ns + path
        ts = parse_time(ev.get("time"))
        if ts is None:
            continue
        matched += 1

        # A denied call is not a use, and it may not even be a real secret: this
        # is exactly where an attacker probes a path that was never provisioned.
        # Track it in the denial table, WITHOUT adding it to `seen`/`namespaces`,
        # so a probed-and-rejected path never enters the hygiene universe as a
        # phantom "never accessed" secret and never counts toward orphan detection.
        error = ev.get("error") or ((ev.get("response") or {}).get("data") or {}).get("error")
        if error:
            who = (ev.get("auth") or {}).get("display_name") or "unknown"
            # Key on the RAW ns ("" for root), same as `key` above, not the "root"
            # display label: denial_table rebuilds "secret" as ns + path below, and
            # doing that with the display label instead bakes a literal "root" onto
            # the front of the path, the same bug the namespace fallback exists to
            # avoid for the main table.
            denials[(ns, path, who)] += 1
            if ts > denial_last_seen.get((ns, path, who), 0):
                denial_last_seen[(ns, path, who)] = ts
            continue

        seen.add(key)
        namespaces[key] = ns or "root"
        op = req.get("operation")
        if op == "read":
            reads[key] += 1
            if ts > last_read.get(key, 0):
                last_read[key] = ts
        elif op in ("update", "create", "patch"):
            writes[key] += 1
            if ts > last_write.get(key, 0):
                last_write[key] = ts

    # The baseline inventory is what makes "never read" visible.
    inventory = []
    if inventory_path:
        with open(inventory_path) as fh:
            for row in csv.DictReader(fh):
                s = row.get("secret")
                if not s:
                    continue
                inventory.append(s)
                namespaces.setdefault(s, row.get("namespace") or "root")

    universe = sorted(set(inventory) | seen)
    orphans = seen - set(inventory) if inventory else set()

    table = []
    for key in universe:
        table.append({
            "secret": key,
            "namespace": namespaces.get(key, "root"),
            "last_read": last_read.get(key),
            "last_write": last_write.get(key),
            "reads": reads.get(key, 0),
            "writes": writes.get(key, 0),
        })

    denial_table = [
        {"namespace": ns or "root", "secret": ns + path, "who": who, "count": n,
         "last_denied": denial_last_seen.get((ns, path, who))}
        for (ns, path, who), n in denials.items()
    ]

    return table, denial_table, {
        "scanned": scanned, "matched": matched,
        "inventory": len(inventory), "orphans": len(orphans),
        "universe": len(universe), "denials": sum(denials.values()),
        "skipped_by_mount": dict(skipped_by_mount),
    }


def parse_time(s):
    """Vault stamps RFC3339 with nanoseconds; strptime tops out at microseconds."""
    if not s:
        return None
    try:
        return int(time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone)
    except ValueError:
        return None


def bucket_for(age_days):
    """Labels are NUMBER-PREFIXED so they sort chronologically.

    Grafana and Splunk both sort bucket labels as strings, so a bare "<=180d" lands
    before "<=30d" and the histogram reads as nonsense. The prefix fixes the ordering
    with no dashboard-side sorting. "never read" is deliberately left unprefixed:
    'n' sorts after the digits, so it stays last, and dashboard queries that filter on
    bucket="never read" keep working untouched.
    """
    if age_days is None:
        return "never read"
    for i, b in enumerate(BUCKETS, start=1):
        if age_days <= b:
            return f"{i} <={b}d"
    return f"{len(BUCKETS) + 1} >{BUCKETS[-1]}d"


def classify(table, now):
    """Attach age + verdict to every row. This is the whole product."""
    for r in table:
        r["read_age"] = None if r["last_read"] is None else (now - r["last_read"]) // DAY
        r["write_age"] = None if r["last_write"] is None else (now - r["last_write"]) // DAY
        r["bucket"] = bucket_for(r["read_age"])
        if r["last_read"] is None and r["writes"] > 0:
            r["verdict"] = "rotated_but_never_read"
        elif r["last_read"] is None:
            r["verdict"] = "never_accessed"
        elif r["read_age"] > 540:
            r["verdict"] = "dormant_over_540d"
        elif r["read_age"] > 365:
            r["verdict"] = "dormant_over_365d"
        else:
            r["verdict"] = "active"
    return table


# ------------------------------------------------------------ outputs ----
def prom_payload(table, stats, denial_table=None):
    """Aggregate ONLY. Cardinality here is (buckets x namespaces), not secrets.

    denial_table is aggregated to (namespace) for the exposed counter, for the same
    reason secret path is never a label anywhere else in this file: a denial counter
    keyed by path or by identity reintroduces the exact cardinality problem this
    tool exists to avoid. Per-path, per-identity denial DETAIL travels as Loki log
    lines instead, the same pattern as the hygiene findings table.
    """
    by_bucket = defaultdict(int)
    by_ns_bucket = defaultdict(int)
    by_verdict = defaultdict(int)
    for r in table:
        by_bucket[r["bucket"]] += 1
        by_ns_bucket[(r["namespace"], r["bucket"])] += 1
        by_verdict[r["verdict"]] += 1

    by_ns_denials = defaultdict(int)
    for d in (denial_table or []):
        by_ns_denials[d["namespace"]] += d["count"]

    out = []
    out.append("# HELP vault_secret_total Secrets known from the baseline inventory plus audit stream.")
    out.append("# TYPE vault_secret_total gauge")
    out.append(f"vault_secret_total {len(table)}")

    out.append("# HELP vault_secret_last_read_age Secrets per last-read age bucket.")
    out.append("# TYPE vault_secret_last_read_age gauge")
    for b, n in sorted(by_bucket.items()):
        out.append(f'vault_secret_last_read_age{{bucket="{esc(b)}"}} {n}')

    out.append("# HELP vault_secret_last_read_age_by_namespace Age bucket split by namespace.")
    out.append("# TYPE vault_secret_last_read_age_by_namespace gauge")
    for (ns, b), n in sorted(by_ns_bucket.items()):
        out.append(f'vault_secret_last_read_age_by_namespace{{namespace="{esc(ns)}",bucket="{esc(b)}"}} {n}')

    out.append("# HELP vault_secret_verdict Secrets per hygiene verdict.")
    out.append("# TYPE vault_secret_verdict gauge")
    for v, n in sorted(by_verdict.items()):
        out.append(f'vault_secret_verdict{{verdict="{esc(v)}"}} {n}')

    out.append("# HELP vault_secret_audit_events_scanned Audit events read in this fold.")
    out.append("# TYPE vault_secret_audit_events_scanned gauge")
    out.append(f"vault_secret_audit_events_scanned {stats['scanned']}")
    out.append("# HELP vault_secret_audit_events_matched KV v2 data-path events folded.")
    out.append("# TYPE vault_secret_audit_events_matched gauge")
    out.append(f"vault_secret_audit_events_matched {stats['matched']}")
    out.append("# HELP vault_secret_inventory_orphans Secrets in audit but absent from inventory (should be 0).")
    out.append("# TYPE vault_secret_inventory_orphans gauge")
    out.append(f"vault_secret_inventory_orphans {stats['orphans']}")

    out.append("# HELP vault_secret_denied_total Denied requests, by namespace. Alert on a rising rate.")
    out.append("# TYPE vault_secret_denied_total counter")
    for ns, n in sorted(by_ns_denials.items()):
        out.append(f'vault_secret_denied_total{{namespace="{esc(ns)}"}} {n}')
    if not by_ns_denials:
        out.append('vault_secret_denied_total{namespace="none"} 0')

    skipped = stats.get("skipped_by_mount") or {}
    if skipped:
        out.append("# HELP vault_secret_events_skipped Events not folded, by the mount_type that excluded them.")
        out.append("# TYPE vault_secret_events_skipped gauge")
        for mount, n in sorted(skipped.items()):
            out.append(f'vault_secret_events_skipped{{mount_type="{esc(mount)}"}} {n}')
    return "\n".join(out) + "\n"


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def push_prometheus(url, body, job=JOB):
    endpoint = f"{url.rstrip('/')}/metrics/job/{job}"
    req = urllib.request.Request(endpoint, data=body.encode(), method="PUT",
                                 headers={"Content-Type": "text/plain; version=0.0.4"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def push_loki(url, table, now, limit=500):
    """Findings as log LINES: per-secret detail without per-secret label cardinality."""
    flagged = [r for r in table if r["verdict"] != "active"]
    flagged.sort(key=lambda r: (-r["writes"], r["secret"]))
    flagged = flagged[:limit]

    streams = defaultdict(list)
    ns_ts = now * 1_000_000_000
    for i, r in enumerate(flagged):
        # Nanosecond-unique timestamps so Loki keeps every line in order.
        ts = str(ns_ts + i)
        line = json.dumps({
            "secret": r["secret"],
            "namespace": r["namespace"],
            "verdict": r["verdict"],
            "read_age_days": "never" if r["read_age"] is None else r["read_age"],
            "write_age_days": "never" if r["write_age"] is None else r["write_age"],
            "reads": r["reads"],
            "writes": r["writes"],
        }, separators=(",", ":"))
        streams[(r["verdict"], r["namespace"])].append([ts, line])

    payload = {"streams": [
        {"stream": {"job": JOB, "verdict": v, "namespace": ns}, "values": vals}
        for (v, ns), vals in streams.items()
    ]}
    req = urllib.request.Request(f"{url.rstrip('/')}/loki/api/v1/push",
                                 data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.status, len(flagged)


def push_loki_denials(url, denial_table, now, limit=500):
    """Denial DETAIL as log lines, same shape as push_loki. Stream labels stay at
    (job, namespace): path and identity live in the line body, never as labels."""
    rows = sorted(denial_table, key=lambda d: -d["count"])[:limit]

    streams = defaultdict(list)
    ns_ts = now * 1_000_000_000
    for i, d in enumerate(rows):
        ts = str(ns_ts + i)
        line = json.dumps({
            "secret": d["secret"],
            "namespace": d["namespace"],
            "who": d["who"],
            "count": d["count"],
            "last_denied": d["last_denied"],
        }, separators=(",", ":"))
        streams[d["namespace"]].append([ts, line])

    payload = {"streams": [
        {"stream": {"job": JOB, "kind": "denial", "namespace": ns}, "values": vals}
        for ns, vals in streams.items()
    ]}
    req = urllib.request.Request(f"{url.rstrip('/')}/loki/api/v1/push",
                                 data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.status, len(rows)


# --------------------------------------------------------------- main ----
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audit", required=True, help='Vault audit log, JSON lines. "-" for stdin')
    ap.add_argument("--inventory", help="baseline secret inventory CSV (secret,namespace,mount)")
    ap.add_argument("--mounts", default="kv",
                     help="comma-separated mount_types to fold, default kv only")
    ap.add_argument("--pushgateway", help="Prometheus Pushgateway base URL")
    ap.add_argument("--loki", help="Loki base URL")
    ap.add_argument("--state-file", help="write the folded table here (the 18-month memory)")
    ap.add_argument("--print", dest="show", action="store_true", help="print a summary")
    ap.add_argument("--limit", type=int, default=500, help="max findings pushed to Loki")
    args = ap.parse_args()

    mounts = tuple(m.strip() for m in args.mounts.split(",") if m.strip())

    now = int(time.time())
    t0 = time.time()
    table, denial_table, stats = fold(args.audit, args.inventory, mounts=mounts)
    classify(table, now)
    elapsed = time.time() - t0

    if not args.inventory:
        print("WARNING: no --inventory given. Secrets never read emit no audit events, "
              "so they cannot appear here. 'never read' will read 0 and be wrong.",
              file=sys.stderr)

    if args.show:
        by_bucket = defaultdict(int)
        by_verdict = defaultdict(int)
        for r in table:
            by_bucket[r["bucket"]] += 1
            by_verdict[r["verdict"]] += 1
        print(f"folded {stats['scanned']:,} events ({stats['matched']:,} matched, "
              f"mounts={','.join(mounts)}) over {stats['universe']:,} secrets in {elapsed:.1f}s")
        if stats["orphans"]:
            print(f"WARNING: {stats['orphans']} secrets seen in audit are missing from the "
                  f"inventory; the inventory is stale.")
        if stats.get("skipped_by_mount"):
            print("\nskipped (mount_type not in --mounts):")
            for m, n in sorted(stats["skipped_by_mount"].items(), key=lambda kv: -kv[1]):
                print(f"  {m:>24}: {n:>8,}")
        print("\nlast-read age buckets:")
        for b in [bucket_for(x) for x in BUCKETS] + [bucket_for(10**6), "never read"]:
            if by_bucket.get(b):
                print(f"  {b:>12}: {by_bucket[b]:>8,}")
        print("\nverdicts:")
        for v, n in sorted(by_verdict.items(), key=lambda kv: -kv[1]):
            print(f"  {v:>24}: {n:>8,}")
        if stats["denials"]:
            print(f"\ndenials: {stats['denials']:,} across {len(denial_table):,} "
                  f"(namespace, path, identity) combinations")

    if args.state_file:
        parent = os.path.dirname(args.state_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.state_file, "w") as fh:
            json.dump({"as_of": now, "secrets": table, "denials": denial_table}, fh)
        print(f"state -> {args.state_file}", file=sys.stderr)

    if args.pushgateway:
        try:
            code = push_prometheus(args.pushgateway, prom_payload(table, stats, denial_table))
            print(f"pushgateway {args.pushgateway}: HTTP {code}", file=sys.stderr)
        except urllib.error.URLError as e:
            print(f"pushgateway push FAILED: {e}", file=sys.stderr)
            return 1

    if args.loki:
        try:
            code, n = push_loki(args.loki, table, now, args.limit)
            print(f"loki {args.loki}: HTTP {code}, {n} findings", file=sys.stderr)
        except urllib.error.URLError as e:
            print(f"loki push FAILED: {e}", file=sys.stderr)
            return 1
        if denial_table:
            try:
                code, n = push_loki_denials(args.loki, denial_table, now, args.limit)
                print(f"loki {args.loki}: HTTP {code}, {n} denial rows", file=sys.stderr)
            except urllib.error.URLError as e:
                print(f"loki denial push FAILED: {e}", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

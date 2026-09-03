#!/usr/bin/env python3
"""Vault credential lease inventory: who has an active leased credential, and when
does it expire.

Covers Azure, AWS, Database and any other engine that issues LEASED, EXPIRING
credentials, as distinct from vault-secret-aggregator.py, which covers static KV v2
secrets. The two are architecturally different and this is why they are separate tools.

WHY THIS IS NOT A FOLD OF THE AUDIT LOG (verified 2026-09-03, see
docs/2026-09-03-SPEC-credential-lease-visibility.md in the private repo for the full
investigation):
  The credential-issuance audit event carries no lease_duration or expire_time at all,
  only a clear-text lease_id. The one API call that DOES return expiry
  (sys/leases/lookup) HMACs its own lease_id in the audit log, both as input and
  output, so it cannot be joined back to the clear-text lease_id from issuance. Role
  TTL config (default_ttl/max_ttl) is also HMAC'd on write. Expiry is simply not
  present in the audit stream at any layer that can be recovered.

  What DOES work, verified: Vault's live API lets you enumerate and inspect active
  leases directly, in clear text:
      vault list sys/leases/lookup/<mount>/creds/<role>/     -> active lease IDs
      vault lease lookup <lease_id>                          -> issue_time, expire_time, ttl
  This tool polls that live API. It is architecturally closer to the KV baseline
  inventory walk than to the audit fold: a lease's expiry is not observable after the
  fact, so you have to ask Vault directly, and you have to keep asking, because leases
  expire on their own between polls.

CARDINALITY (same rule as vault-secret-aggregator.py): never emit a lease ID or a
credential path as a Prometheus label. Aggregate gauges are grouped by mount and role
only. Per-lease detail travels as Loki log lines / JSONL rows, never as labels.

ENGINE COVERAGE: only the `database` secret engine has been tested against a real
Vault, a real backend, and a real issued lease. `aws` and `azure` are wired in on the
assumption that they follow the same LIST-then-lookup shape (both issue under
`<mount>/creds/<role>`), which is architecturally likely but UNVERIFIED. Every finding
this tool produces for aws/azure carries `"verified": false` so a downstream dashboard
can flag it visually rather than presenting it with the same confidence as database
findings.

Usage:
  export VAULT_ADDR=https://vault.example.com:8200
  export VAULT_TOKEN=...   # a token with read access to sys/mounts, <mount>/roles,
                            # sys/leases/lookup/*, and list on the same
  ./vault-lease-inventory.py --print
  ./vault-lease-inventory.py --out leases.jsonl --pushgateway http://<host>:9091 --loki http://<host>:3100
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

JOB = "vault-lease-inventory"

# Days-to-expiry buckets. Numbered so labels sort correctly, same convention as
# vault-secret-aggregator.py's bucket_for().
BUCKETS_HOURS = [1, 24, 24 * 7, 24 * 30]  # <=1h, <=1d, <=7d, <=30d, then >30d

# Engine types this tool knows how to poll, and whether that shape has been verified
# against a real backend. Every engine here is assumed to issue credentials under
# "<mount>/creds/<role>", which is confirmed for database and is Vault's documented
# default for aws and azure, but only database has been tested end to end.
ENGINE_TYPES = {
    "database": {"creds_prefix": "creds", "verified": True},
    "aws":      {"creds_prefix": "creds", "verified": False},
    "azure":    {"creds_prefix": "creds", "verified": False},
}


def vault_request(addr, token, method, path, body=None):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                  headers={"X-Vault-Token": token,
                                           "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None   # no data at this path; normal for "no active leases"
        raise


def splunk_session_key_from_stdin():
    """Read the session key Splunk passes on stdin for a scripted input configured
    with `passAuth = splunk-system-user`. VERIFIED 2026-09-03 against a real Splunk
    10.4.3 instance: this is a real session key usable as `Authorization: Splunk
    <key>` against the local REST API, not a username:password pair. The FIRST
    invocation after a Splunk restart can arrive with empty stdin (observed live);
    treat that as "not available yet", not a fatal error, since Splunk itself will
    retry on the next scheduled interval.
    """
    if sys.stdin.isatty():
        return None
    key = sys.stdin.read().strip()
    return key or None


def vault_token_from_splunk(realm_and_name, mgmt_uri="https://localhost:8089", verify=False):
    """Fetch a credential Splunk's own storage/passwords already holds, using the
    session key Splunk itself handed this script. Never puts the Vault token in
    inputs.conf, an env var, or anywhere else that could show up in `ps` or a
    world-readable conf file: it stays inside Splunk's own encrypted credential
    store (encr_password, encrypted with the instance's splunk.secret) until the
    moment this process needs it, over the loopback-only management port.

    realm_and_name: "<realm>:<name>" as stored via storage/passwords, e.g.
    "vault_audit_hygiene:vault_lease_poller_token".
    """
    session_key = splunk_session_key_from_stdin()
    if not session_key:
        return None
    realm, _, name = realm_and_name.partition(":")
    if not name:
        raise SystemExit(f"--splunk-credential expects realm:name, got {realm_and_name!r}")
    url = (f"{mgmt_uri.rstrip('/')}/servicesNS/nobody/vault_audit_hygiene/"
           f"storage/passwords/{urllib.parse.quote(realm, safe='')}"
           f"%3A{urllib.parse.quote(name, safe='')}%3A?output_mode=json")
    req = urllib.request.Request(url, headers={"Authorization": f"Splunk {session_key}"})
    ctx = None
    if not verify:
        import ssl
        ctx = ssl._create_unverified_context()  # local loopback, Splunk's own cert
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        data = json.loads(resp.read())
    return data["entry"][0]["content"]["clear_password"]


def list_keys(addr, token, path):
    r = vault_request(addr, token, "LIST", path)
    if r is None:
        return []
    return (r.get("data") or {}).get("keys") or []


def parse_iso(s):
    if not s:
        return None
    # Vault emits RFC3339 with sub-second precision and a numeric UTC offset.
    return datetime.fromisoformat(s).timestamp()


def bucket_for_seconds(remaining_s):
    if remaining_s is None:
        return "unknown"
    if remaining_s <= 0:
        return "0 expired"
    hours = remaining_s / 3600
    for i, h in enumerate(BUCKETS_HOURS, start=1):
        if hours <= h:
            return f"{i} <={h_label(h)}"
    return f"{len(BUCKETS_HOURS) + 1} >{h_label(BUCKETS_HOURS[-1])}"


def h_label(hours):
    if hours < 24:
        return f"{int(hours)}h"
    return f"{int(hours // 24)}d"


# ---------------------------------------------------------------- poll ----
def poll(addr, token, engine_types=("database",)):
    """Walk sys/mounts for the requested engine types, enumerate roles, enumerate
    active leases per role, and look up each lease's real expiry.

    Returns (rows, stats). Never groups or aggregates here; that happens in fold().
    """
    mounts = (vault_request(addr, token, "GET", "sys/mounts") or {}).get("data") or {}
    rows = []
    stats = {"mounts_scanned": 0, "roles_scanned": 0, "leases_found": 0,
              "lookup_failures": 0, "by_engine_type": defaultdict(int)}

    for mount_path, info in mounts.items():
        etype = info.get("type")
        if etype not in engine_types:
            continue
        cfg = ENGINE_TYPES.get(etype, {"creds_prefix": "creds", "verified": False})
        stats["mounts_scanned"] += 1
        stats["by_engine_type"][etype] += 1

        roles = list_keys(addr, token, f"{mount_path}roles")
        for role in roles:
            stats["roles_scanned"] += 1
            lease_ids = list_keys(
                addr, token, f"sys/leases/lookup/{mount_path}{cfg['creds_prefix']}/{role}/")
            for lid in lease_ids:
                full_lease_id = f"{mount_path}{cfg['creds_prefix']}/{role}/{lid}"
                detail = vault_request(addr, token, "PUT", "sys/leases/lookup",
                                        {"lease_id": full_lease_id})
                if detail is None:
                    # Lease expired or was revoked between LIST and this lookup.
                    # Not an error: leases are moving targets, this is expected.
                    stats["lookup_failures"] += 1
                    continue
                d = detail.get("data") or {}
                issue_ts = parse_iso(d.get("issue_time"))
                expire_ts = parse_iso(d.get("expire_time"))
                stats["leases_found"] += 1
                rows.append({
                    "mount": mount_path.rstrip("/"),
                    "engine_type": etype,
                    "role": role,
                    "lease_id": full_lease_id,
                    "issue_time": issue_ts,
                    "expire_time": expire_ts,
                    "ttl_seconds": d.get("ttl"),
                    "renewable": d.get("renewable"),
                    "verified_engine": cfg["verified"],
                })
    stats["by_engine_type"] = dict(stats["by_engine_type"])
    return rows, stats


def classify(rows, now):
    for r in rows:
        remaining = None if r["expire_time"] is None else r["expire_time"] - now
        r["seconds_to_expiry"] = remaining
        r["days_to_expiry"] = None if remaining is None else round(remaining / 86400, 2)
        r["bucket"] = bucket_for_seconds(remaining)
        r["age_seconds"] = None if r["issue_time"] is None else now - r["issue_time"]
        # Stamped so a Splunk monitor:// tailing an appended file can chart trend over
        # repeated polls, the same shape as the audit log growing over time. Without
        # this, every row from every poll looks identical and Splunk has no way to
        # tell "this poll" from "three polls ago".
        r["polled_at"] = now
    return rows


# ------------------------------------------------------------ outputs ----
def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def prom_payload(rows, stats):
    """Aggregate only. Cardinality is (mount x role x bucket), never per-lease."""
    by_bucket = defaultdict(int)
    by_mount_role_bucket = defaultdict(int)
    for r in rows:
        by_bucket[r["bucket"]] += 1
        by_mount_role_bucket[(r["mount"], r["role"], r["bucket"])] += 1

    out = []
    out.append("# HELP vault_lease_total Active leased credentials found this poll.")
    out.append("# TYPE vault_lease_total gauge")
    out.append(f"vault_lease_total {len(rows)}")

    out.append("# HELP vault_lease_expiry_bucket Active leases per days-to-expiry bucket.")
    out.append("# TYPE vault_lease_expiry_bucket gauge")
    for b, n in sorted(by_bucket.items()):
        out.append(f'vault_lease_expiry_bucket{{bucket="{esc(b)}"}} {n}')

    out.append("# HELP vault_lease_expiry_by_mount_role Expiry bucket split by mount and role.")
    out.append("# TYPE vault_lease_expiry_by_mount_role gauge")
    for (mount, role, b), n in sorted(by_mount_role_bucket.items()):
        out.append(f'vault_lease_expiry_by_mount_role{{mount="{esc(mount)}",role="{esc(role)}",bucket="{esc(b)}"}} {n}')

    out.append("# HELP vault_lease_poll_mounts_scanned Leased-engine mounts scanned this poll.")
    out.append("# TYPE vault_lease_poll_mounts_scanned gauge")
    out.append(f"vault_lease_poll_mounts_scanned {stats['mounts_scanned']}")
    out.append("# HELP vault_lease_poll_lookup_failures Leases listed but gone by the time they were looked up (expired/revoked mid-poll, expected).")
    out.append("# TYPE vault_lease_poll_lookup_failures gauge")
    out.append(f"vault_lease_poll_lookup_failures {stats['lookup_failures']}")
    return "\n".join(out) + "\n"


def push_prometheus(url, body, job=JOB):
    endpoint = f"{url.rstrip('/')}/metrics/job/{job}"
    req = urllib.request.Request(endpoint, data=body.encode(), method="PUT",
                                  headers={"Content-Type": "text/plain; version=0.0.4"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def push_loki(url, rows, now, limit=1000):
    """Per-lease detail as Loki log lines. Stream labels are (job, mount, engine_type)
    only, never lease_id or role: role cardinality is usually low but treat it the
    same as everywhere else in this repo, on principle."""
    ranked = sorted(rows, key=lambda r: (r["seconds_to_expiry"] if r["seconds_to_expiry"] is not None else 10**12))
    ranked = ranked[:limit]

    streams = defaultdict(list)
    ns_ts = now * 1_000_000_000
    for i, r in enumerate(ranked):
        ts = str(ns_ts + i)
        line = json.dumps({
            "mount": r["mount"], "role": r["role"], "lease_id": r["lease_id"],
            "bucket": r["bucket"], "days_to_expiry": r["days_to_expiry"],
            "renewable": r["renewable"], "verified_engine": r["verified_engine"],
        }, separators=(",", ":"))
        streams[(r["mount"], r["engine_type"])].append([ts, line])

    payload = {"streams": [
        {"stream": {"job": JOB, "mount": m, "engine_type": et}, "values": vals}
        for (m, et), vals in streams.items()
    ]}
    req = urllib.request.Request(f"{url.rstrip('/')}/loki/api/v1/push",
                                  data=json.dumps(payload).encode(), method="POST",
                                  headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.status, len(ranked)


# --------------------------------------------------------------- main ----
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vault-addr", default=os.environ.get("VAULT_ADDR"),
                     help="defaults to $VAULT_ADDR")
    ap.add_argument("--engines", default="database",
                     help="comma-separated engine types to poll, default database only "
                          "(the only one verified end to end; add aws/azure explicitly)")
    ap.add_argument("--pushgateway", help="Prometheus Pushgateway base URL")
    ap.add_argument("--loki", help="Loki base URL")
    ap.add_argument("--out", help="append one JSON line per active lease here, for a Splunk monitor:// input")
    ap.add_argument("--stdout", action="store_true",
                     help="write JSON lines to stdout instead, for a Splunk SCRIPTED input "
                          "(Splunk captures this process's stdout directly; do not combine with --print)")
    ap.add_argument("--splunk-credential",
                     help="realm:name of a Vault token already stored in Splunk's own "
                          "storage/passwords. Requires this script be invoked by a Splunk "
                          "scripted input configured with passAuth = splunk-system-user, "
                          "which hands a session key to this process on stdin. Overrides "
                          "$VAULT_TOKEN when the session key is present.")
    ap.add_argument("--splunk-mgmt-uri", default="https://localhost:8089",
                     help="Splunk management port, for --splunk-credential. Default assumes "
                          "this script runs on the same host as splunkd.")
    ap.add_argument("--print", dest="show", action="store_true")
    args = ap.parse_args()

    addr = args.vault_addr
    token = os.environ.get("VAULT_TOKEN")
    if args.splunk_credential:
        try:
            splunk_token = vault_token_from_splunk(args.splunk_credential, args.splunk_mgmt_uri)
        except Exception as e:
            # Splunk's own scheduler will retry next interval. Exiting nonzero here is
            # correct: it shows up as a scripted-input error in Splunk's own health
            # checks, which is exactly where an operator should see it, rather than
            # silently falling back to a stale or missing token.
            sys.exit(f"Could not retrieve Vault token from Splunk storage/passwords "
                      f"({args.splunk_credential}): {e}")
        if splunk_token:
            token = splunk_token
        # else: session key was empty (the documented first-run gap after a Splunk
        # restart). Fall through to $VAULT_TOKEN if one happens to be set; otherwise
        # the check below exits cleanly and Splunk's scheduler retries next interval.
    if not addr or not token:
        sys.exit("Set VAULT_ADDR (or --vault-addr) and either VAULT_TOKEN or "
                 "--splunk-credential. Never pass the token as a CLI argument, it "
                 "lands in shell history.")

    engines = tuple(e.strip() for e in args.engines.split(",") if e.strip())
    unverified = [e for e in engines if not ENGINE_TYPES.get(e, {}).get("verified")]
    if unverified:
        print(f"WARNING: polling {unverified}, which have never been verified against a "
              f"real backend. Only 'database' has. Treat their numbers as unproven.",
              file=sys.stderr)

    now = time.time()
    rows, stats = poll(addr, token, engines)
    classify(rows, now)

    if args.show:
        # --stdout is Splunk's event stream: nothing else may ever land on stdout
        # while it is active, or a human-readable line becomes a malformed "event".
        out = sys.stderr if args.stdout else sys.stdout
        print(f"scanned {stats['mounts_scanned']} mount(s), {stats['roles_scanned']} role(s), "
              f"found {stats['leases_found']} active lease(s) "
              f"({stats['lookup_failures']} expired mid-poll, that is expected)", file=out)
        print("by engine type:", stats["by_engine_type"], file=out)
        by_bucket = defaultdict(int)
        for r in rows:
            by_bucket[r["bucket"]] += 1
        print("\ndays-to-expiry buckets:", file=out)
        for b in sorted(by_bucket):
            print(f"  {b:>12}: {by_bucket[b]:>6,}", file=out)
        print("\nleases, soonest expiry first:", file=out)
        for r in sorted(rows, key=lambda r: r["seconds_to_expiry"] or 10**12)[:20]:
            flag = "" if r["verified_engine"] else "  [UNVERIFIED ENGINE]"
            print(f"  {r['mount']:<20} {r['role']:<15} {r['days_to_expiry']:>7} days{flag}", file=out)

    if args.out:
        # Append, not overwrite: this is meant to be run periodically (leases expire
        # between polls, a one-shot snapshot goes stale within the shortest TTL in the
        # estate) and tailed by a Splunk monitor:// input the same way audit.jsonl is,
        # so history accumulates in the file rather than being discarded each run.
        parent = os.path.dirname(args.out)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.out, "a") as fh:
            for r in rows:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        print(f"snapshot -> {args.out} ({len(rows)} rows appended)", file=sys.stderr)

    if args.stdout:
        # For a Splunk SCRIPTED input: splunkd reads this process's stdout directly as
        # the event stream, one event per line, no intermediate file, no external
        # cron. Nothing but JSON lines belongs here; --print's human summary goes to
        # stderr for exactly this reason, so the two can be combined for debugging
        # without corrupting what Splunk ingests.
        for r in rows:
            sys.stdout.write(json.dumps(r, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    if args.pushgateway:
        try:
            code = push_prometheus(args.pushgateway, prom_payload(rows, stats))
            print(f"pushgateway {args.pushgateway}: HTTP {code}", file=sys.stderr)
        except urllib.error.URLError as e:
            print(f"pushgateway push FAILED: {e}", file=sys.stderr)
            return 1

    if args.loki and rows:
        try:
            code, n = push_loki(args.loki, rows, int(now))
            print(f"loki {args.loki}: HTTP {code}, {n} lease rows", file=sys.stderr)
        except urllib.error.URLError as e:
            print(f"loki push FAILED: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

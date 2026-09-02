#!/usr/bin/env python3
"""Generate a realistic Vault audit-log sample for loading into Splunk (or folding directly).

The event schema is copied field-for-field from a REAL Vault audit entry captured from a
live HCP Vault cluster (see docs/how-it-works.md). Only the namespaces, paths, and
identities are synthetic, shaped like a large enterprise estate: several namespaces, a
Kubernetes-dominated auth mix, GitLab CI pipelines, and a legacy auth mount nobody
remembers mounting.

Nothing here is a credential. Secret values are HMAC-SHA256 placeholders exactly as the
Vault audit device emits them; the audit log never contains a plaintext secret.

Usage:
    python3 generate-sample.py                        # defaults: 10k paths, 80k events
    python3 generate-sample.py --paths 50000 --events 400000
    python3 generate-sample.py --expected             # print ground-truth R1 buckets only
"""

import argparse
import hashlib
import json
import os
import random
import sys
import time

# --- Enterprise-shaped estate profile (namespaces, auth mix, engine mix) -------------
# Namespace names are illustrative. Swap them for your own before demoing internally.
NAMESPACES = [
    ("", "root"),
    ("pci/", "pci"),         # regulated scope; metadata only, always.
    ("platform/", "platform"),
    ("apps/", "apps"),
    ("data/", "data"),
]
NS_WEIGHTS = [0.42, 0.10, 0.16, 0.16, 0.16]

KV_MOUNTS = ["secret", "kv-apps", "kv-infra", "kv-gitlab", "kv-platform"]

# Kubernetes dominates auth in most large estates, ~85% of mounts here.
AUTH_METHODS = (
    ["kubernetes"] * 85 + ["jwt"] * 5 + ["approle"] * 3 + ["token"] * 2
    + ["oidc"] * 1 + ["userpass"] * 1 + ["ldap"] * 1 + ["cert"] * 1
    + ["aws"] * 1
)
# Dead-config hygiene: a legacy auth mount that was supposedly decommissioned but is
# still mounted and still taking a trickle of logins. Leftover config after a platform
# migration is exactly the class of finding these dashboards exist to surface.
DEAD_AUTH = "cloudfoundry"

APP_PREFIXES = ["payments", "billing", "crm", "ordering", "inventory", "identity",
                "notify", "search", "provisioning", "analytics"]

DAY = 86400
WINDOW_DAYS = 540  # 18 months, the usual horizon for a dormancy audit
BUCKETS = [30, 90, 180, 365, 540]


def hmac_placeholder(seed: str) -> str:
    """Shape-accurate stand-in for what the audit device writes. Not a real hash of a
    real secret; there is no secret here to hash."""
    return "hmac-sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def build_paths(n, rng):
    """Return [(namespace, mount, logical_path)]: n distinct KV v2 secrets."""
    out = []
    for i in range(n):
        ns = rng.choices([n_ for n_, _ in NAMESPACES], weights=NS_WEIGHTS, k=1)[0]
        mount = KV_MOUNTS[i % len(KV_MOUNTS)]
        app = APP_PREFIXES[i % len(APP_PREFIXES)]
        out.append((ns, mount, f"{app}-{i // 40:04d}/svc-{i % 40:02d}/credential"))
    return out


def make_identity(rng):
    """Kubernetes SA or GitLab pipeline: the two identities worth tracing a read back to."""
    if rng.random() < 0.85:
        cluster = rng.randint(1, 600)
        sa = rng.choice(APP_PREFIXES)
        return (
            "kubernetes",
            f"kubernetes-eks-prod-{cluster:03d}",
            f"sa-{sa}",
            {"service_account_name": f"sa-{sa}",
             "service_account_namespace": sa,
             "kubernetes_cluster": f"eks-prod-{cluster:03d}"},
        )
    pipeline = rng.randint(100000, 999999)
    project = rng.choice(APP_PREFIXES)
    return (
        "jwt",
        f"gitlab-{project}",
        f"pipeline-{pipeline}",
        {"gitlab_project": f"platform/{project}", "pipeline_id": str(pipeline)},
    )


def audit_event(ts, ns, mount, logical, operation, rng, api_prefix="data"):
    """One Vault audit 'response' event, in the real device schema."""
    auth_method, mount_name, principal, meta = make_identity(rng)
    path = f"{mount}/{api_prefix}/{logical}"
    display = f"{mount_name}:{principal}"
    ev = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts))
                + f".{rng.randint(0, 999999999):09d}Z",
        "type": "response",
        "auth": {
            "accessor": hmac_placeholder(f"accessor{principal}"),
            "client_token": hmac_placeholder(f"token{principal}"),
            "display_name": display,
            "entity_id": hashlib.sha256(display.encode()).hexdigest()[:32],
            "metadata": meta,
            "policies": ["default", f"{mount}-reader"],
            "token_policies": ["default", f"{mount}-reader"],
            "token_ttl": 3600,
            "token_type": "service",
        },
        "request": {
            "id": hashlib.sha256(f"{ts}{path}{rng.random()}".encode()).hexdigest()[:36],
            "operation": operation,
            "path": path,
            "mount_type": "kv",
            "mount_class": "secret",
            "mount_point": f"{mount}/",
            "mount_accessor": f"kv_{hashlib.sha256(mount.encode()).hexdigest()[:8]}",
            "mount_running_version": "v0.26.2+builtin",
            "namespace": {"id": hashlib.sha256(ns.encode()).hexdigest()[:5], "path": ns},
            "remote_address": f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
            "client_id": hashlib.sha256(display.encode()).hexdigest()[:32],
            "headers": {"user-agent": ["Go-http-client/2.0"]},
        },
        "response": {
            "mount_type": "kv",
            "mount_class": "secret",
            "mount_point": f"{mount}/",
            "data": {
                "data": {"password": hmac_placeholder(path),
                         "username": hmac_placeholder(path + "u")},
                "metadata": {"created_time": hmac_placeholder(path + "c"),
                             "custom_metadata": None, "destroyed": False,
                             "version": rng.randint(1, 12)},
            },
        },
    }
    return ev


def login_event(ts, ns, method, rng, dead=False):
    """An auth login; feeds R7 (auth method breakdown) and R11 (dead mount still live)."""
    _, mount_name, principal, meta = make_identity(rng)
    display = f"auth-{method}:{principal}"
    return {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts))
                + f".{rng.randint(0, 999999999):09d}Z",
        "type": "response",
        "auth": {"display_name": display, "metadata": meta,
                 "entity_id": hashlib.sha256(display.encode()).hexdigest()[:32],
                 "policies": ["default"], "token_ttl": 3600, "token_type": "service"},
        "request": {
            "id": hashlib.sha256(f"{ts}{method}{rng.random()}".encode()).hexdigest()[:36],
            "operation": "update",
            "path": f"auth/{method}{'-legacy' if dead else ''}/login",
            "mount_type": method,
            "mount_class": "auth",
            "mount_point": f"auth/{method}/",
            "namespace": {"id": hashlib.sha256(ns.encode()).hexdigest()[:5], "path": ns},
            "remote_address": f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        },
        "response": {"mount_type": method, "mount_class": "auth"},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paths", type=int, default=10_000, help="distinct KV v2 secrets")
    ap.add_argument("--events", type=int, default=80_000, help="KV read/write events")
    ap.add_argument("--logins", type=int, default=20_000, help="auth login events")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  "samples", "vault-audit-sample.jsonl"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--window-days", type=int, default=WINDOW_DAYS,
                    help="how far back events reach. Splunk DROPS events older than the "
                         "index frozenTimePeriodInSecs; if your index has short "
                         "retention, shrink this to fit or the old buckets come back empty.")
    ap.add_argument("--expected", action="store_true",
                    help="print ground-truth R1 buckets without writing the file")
    args = ap.parse_args()

    window = args.window_days
    rng = random.Random(args.seed)
    now = int(time.time())
    paths = build_paths(args.paths, rng)

    # Access shape: 15% never read at all (the dormant secrets R1 exists to surface),
    # 25% hot and recent, the rest spread back across the 18-month window.
    never_n = int(args.paths * 0.15)
    hot_n = int(args.paths * 0.25)
    never = paths[:never_n]
    readable = paths[never_n:]
    weights = [12.0] * hot_n + [0.4] * (len(readable) - hot_n)

    last_read = {}
    events = []

    for ns, mount, logical in never:
        # Never READ, but many are still being WRITTEN by a rotation job. A secret that
        # is rotated forever and read by nothing is pure waste, and it is invisible to
        # any view that inspects secrets one at a time; nothing about it looks wrong.
        if rng.random() < 0.45:
            for _ in range(rng.randint(2, 14)):
                ts = now - rng.randint(0, min(180, window) * DAY)
                events.append(audit_event(ts, ns, mount, logical, "update", rng))

    for _ in range(args.events):
        ns, mount, logical = rng.choices(readable, weights=weights, k=1)[0]
        # Hot paths cluster in the recent past; cold ones spread across the window.
        span = min(45, window) if rng.random() < 0.72 else window
        ts = now - rng.randint(0, span * DAY)
        op = "read" if rng.random() < 0.94 else "update"
        events.append(audit_event(ts, ns, mount, logical, op, rng))
        if op == "read":
            key = ns + f"{mount}/data/{logical}"
            last_read[key] = max(last_read.get(key, 0), ts)

    for _ in range(args.logins):
        ns = rng.choices([n for n, _ in NAMESPACES], weights=NS_WEIGHTS, k=1)[0]
        ts = now - rng.randint(0, min(90, window) * DAY)
        events.append(login_event(ts, ns, rng.choice(AUTH_METHODS), rng))
    # R11: a thin, steady trickle on the supposedly-decommissioned legacy auth mount.
    for _ in range(max(40, args.logins // 400)):
        ts = now - rng.randint(0, min(90, window) * DAY)
        events.append(login_event(ts, "", DEAD_AUTH, rng, dead=True))

    # --- ground truth, so the Splunk result can be checked against a known answer ----
    hist = {}
    for ns, mount, logical in paths:
        key = ns + f"{mount}/data/{logical}"
        ts = last_read.get(key)
        if ts is None:
            hist["never read"] = hist.get("never read", 0) + 1
            continue
        age = (now - ts) // DAY
        label = next((f"<= {b}d" for b in BUCKETS if age <= b), f"> {BUCKETS[-1]}d")
        hist[label] = hist.get(label, 0) + 1

    print("Ground truth: R1 last-read age buckets (what Splunk must reproduce):")
    for label in [f"<= {b}d" for b in BUCKETS] + [f"> {BUCKETS[-1]}d", "never read"]:
        if hist.get(label):
            print(f"  {label:>12}: {hist[label]:>8,}")
    print(f"  {'TOTAL paths':>12}: {args.paths:>8,}")
    print("\nNote: 'never read' is only knowable from the baseline inventory "
          "(vault_secret_inventory.csv); those secrets emit no read event by definition.")

    if args.expected:
        return

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rng.shuffle(events)  # arrive interleaved, like a real stream
    with open(args.out, "w") as f:
        for ev in events:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")

    # Baseline inventory lookup: the answer to "never accessed". Against a real cluster
    # this comes from a one-time KV metadata walk; here we just know it.
    inv = os.path.join(os.path.dirname(args.out), "vault_secret_inventory.csv")
    with open(inv, "w") as f:
        f.write("secret,namespace,mount\n")
        for ns, mount, logical in paths:
            f.write(f'"{ns}{mount}/data/{logical}","{ns or "root"}","{mount}"\n')

    size = os.path.getsize(args.out) / 1e6
    print(f"\nwrote {len(events):,} events -> {args.out} ({size:.1f} MB)")
    print(f"wrote {len(paths):,} inventory rows -> {inv}")


if __name__ == "__main__":
    sys.exit(main())

# Grafana

The same answers without Splunk: identical numbers, identical dataset, no SIEM involved.

![Vault Secret Hygiene overview](../docs/images/grafana-hygiene-overview.jpg)

## Walkthroughs

| | |
|---|---|
| [Find stale secrets](scenarios/01-find-stale-secrets.md) | The cleanup list, and the one input without which the headline number is silently wrong |
| [Denied requests](scenarios/02-denied-requests.md) | A rising denial count against one path, worth an alert |
| [Credential lease visibility](scenarios/03-credential-lease-visibility.md) | Azure/AWS/Database, live-polled not audit-folded. Only Database is verified |

## Architecture

```
Vault audit device ──► (file tail, or stdout captured as pod logs) ──► vault-secret-aggregator.py
                                                                              │
                        folds to (namespace, path) -> last_read, last_write, reads, writes,
                                  plus denials -> (namespace, path, identity) -> count
                                                                              │
                    ┌─────────────────────┬───────────────────────────────────┴──┐
                    ▼                     ▼                                      ▼
        bucket COUNTS ──► Prometheus   denial COUNT (namespace only) ──► Prometheus
        (a handful of series)                                                    │
                    │            per-secret FINDINGS, denial DETAIL ──► Loki (log lines)
                    └─────────────────────┬─────────────────────────────────────┘
                                          ▼
                                       Grafana
```

**Why not just query Loki.** You cannot ask LogQL for "max timestamp per secret path" across
hundreds of thousands of paths; path as a stream label is that many active series and it
kills the index. So the fold happens in a process, and only aggregates cross the wire.
Per-secret and per-denial detail travel as log lines, never as labels. The same rule applies
to the denial counter: it is exposed per namespace only, never per path or per identity.

**Why findings are stamped "now".** A finding is an observation made today about history.
It also keeps them inside Loki's `reject_old_samples` window, which would otherwise reject
an 18-month-old timestamp outright.

**Nothing in your stack changes.** The aggregator pushes (Prometheus Pushgateway + Loki push
API), so there is no scrape config to edit and no existing pipeline to touch.

## Files

| File | What it is |
|---|---|
| `dashboards/vault-secret-hygiene.json` | 8-panel dashboard. Prometheus for aggregates, Loki for the findings and denial tables |
| `dashboards/vault-lease-visibility.json` | 7-panel dashboard for leased credentials (Azure/AWS/Database). Live-polled, not audit-folded, see below |
| `scripts/vault-secret-aggregator.py` | The KV hygiene fold. Grafana-only: Splunk does this fold itself in SPL |
| `scripts/tests/test_aggregator.py` | Fixture-based tests for the aggregator above |

`scripts/vault-lease-inventory.py` is the lease poller behind the dashboard above.
Splunk needs its own separate copy (scripted inputs can only run from an app's own
`bin/`), so treat this one as the source of truth and keep them in sync by hand if you
change it. See [Credential lease visibility](scenarios/03-credential-lease-visibility.md).

⚠️ **Change the datasource UIDs before importing.** They are inlined in the JSON and still
point at the environment it was built in. Replace them with your own Prometheus and Loki
UIDs (Grafana → Connections → Data sources → the UID is in the URL) or every panel comes up
empty. Built against Grafana 10.2, `schemaVersion 38`.

## Run it

```bash
python3 scripts/vault-secret-aggregator.py \
    --audit       /path/to/vault-audit.log \
    --inventory   /path/to/vault_secret_inventory.csv \
    --pushgateway http://<pushgateway-host>:9091 \
    --loki        http://<loki-host>:3100 \
    --state-file  .state/vault-secret-state.json \
    --print
```

Drop `--pushgateway` and `--loki` to print the table locally; that needs nothing but Python 3.

**`--audit` accepts `-` for stdin,** for an audit device that writes to stdout rather than a
file on disk (a Kubernetes sidecar's pod logs, for instance):

```bash
kubectl logs -n vault sts/vault -c vault --since=24h | \
    python3 scripts/vault-secret-aggregator.py --audit - --inventory inv.csv --print
```

**`--mounts` controls which engines fold, default `kv` only.** The `/data/` path
requirement is a KV v2 API artifact and is enforced only for the `kv` mount type; add
others and their paths fold without it:

```bash
--mounts kv,database,pki
```

Anything excluded is counted, not silently dropped: `--print` names every mount type it
skipped and how many events each cost, and the same counts are pushed as
`vault_secret_events_skipped{mount_type=...}`.

**`--inventory` is not optional.** A secret nobody has ever read leaves no trace in the audit
log, so nothing derived from logs can find it. It exists only in that file. Without it the
headline number is silently wrong. The aggregator warns if you omit it.

**`--state-file` is the eighteen-month memory.** In production it has to be checkpointed to
disk. Lose it and the clock resets to zero.

## Denials

A denied request (any response carrying a non-empty `error`) is folded separately from
reads and writes, and never marks a secret as accessed. See
[Denied requests](scenarios/02-denied-requests.md) for how to read the panel and where the
count versus the detail live.

⚠️ **`request.remote_address` may not carry the true client IP** behind a load balancer or
ingress that terminates TLS and proxies to Vault. If yours does, every denial can appear to
share one source address. Confirm what your ingress preserves before building attribution
logic on top of this field.

## Root namespace and Enterprise

Open-source Vault audit devices verified here emit **only** `request.namespace.id`, never
`path` (namespaces are Enterprise-only in the first place, so an open-source device has
nothing to put in `path`). The aggregator prefers `path`, falls back to `id`, then to no
namespace at all:

⚠️ **Whether Vault Enterprise emits `path` alongside `id` is unconfirmed here.** If it does
not, every namespace collapses into one on a namespace-per-tenant estate, silently. The
fallback handles it either way, but treat the "which field does my Enterprise cluster
actually write" question as open until you have checked one real audit entry from it.

Root is normalized specially: Vault's root namespace has the fixed id `"root"`, not an
empty one, so without normalization an id-only device would produce keys like
`"rootkv/data/app/db"` while a path-based device produces `"kv/data/app/db"` for the same
secret. Both now resolve to the same key.

## Credential lease visibility (Azure / AWS / Database)

A separate tool, `scripts/vault-lease-inventory.py`, because it is a separate problem.
The audit log never records lease expiry, at any layer, verified against a real Vault
and a real issued credential. See
[Credential lease visibility](scenarios/03-credential-lease-visibility.md) for the full
finding and how to run the poller. Only the `database` engine has been proven end to
end; AWS and Azure rows on the dashboard are flagged `UNVERIFIED ENGINE` rather than
presented with equal confidence.

## ⚠️ The findings table accumulates across runs

Findings and denial detail are pushed to Loki as log lines stamped now, so **every fold
appends a fresh copy**. Two folds inside the dashboard's time window would show every
secret twice without help.

The dashboard's findings and denial panels both carry a `groupBy` transform (group by
secret path, or by secret path plus identity for denials, `lastNotNull` for every other
column), which makes the panel idempotent across repeated folds. That is why the table
columns are named `namespace (lastNotNull)`, `reads (lastNotNull)`, and so on: that suffix
is the transform's own output naming, not decoration. The real fix is still to stop using a
log stream as a table: the aggregator's state belongs in SQLite or Postgres, queried
directly. This transform is the workaround until that exists.

The aggregate panels are unaffected. Prometheus gauges are replaced wholesale on each push,
so the tiles and the histogram always show the latest fold only.

## Tests

```bash
python3 grafana/scripts/tests/test_aggregator.py -v
```

Stdlib only, fixture-based, no live Grafana or Prometheus needed. Covers: the namespace
fallback (path present, id-only, neither), root normalization, mount filtering with the
default preserved, denials never counting as reads or entering the hygiene table, stdin
producing identical output to a file, and the denial Prometheus counter carrying no path or
identity label.

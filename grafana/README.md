# Grafana

The same answer without Splunk: identical numbers, identical dataset, no SIEM involved.
Useful if you don't want another Splunk workload, or if the asset shouldn't depend on one.

---

## Architecture

```
Vault audit device ──► (Fluent Bit / file tail) ──► vault-secret-aggregator.py
                                                        │
                    folds to (namespace, path) -> last_read, last_write, reads, writes
                                                        │
                          ┌─────────────────────────────┴──────────────────────────┐
                          ▼                                                        ▼
              bucket COUNTS ──► Prometheus                    per-secret FINDINGS ──► Loki
              (a handful of series)                           (log lines, stamped now)
                          └─────────────────────────────┬──────────────────────────┘
                                                        ▼
                                                     Grafana
```

**Why not just query Loki for it.** You cannot ask LogQL for "max timestamp per secret path"
across hundreds of thousands of paths. Path as a stream label is that many active series, and
it kills the index. So the fold happens in a process, and only aggregates cross the wire.
Per-secret detail travels as log **lines** (cheap), never as labels (ruinous).

**Why findings are stamped "now".** A finding is an observation made today about history. It
also means they sail past Loki's `reject_old_samples` window, which would otherwise refuse an
18-month-old timestamp outright.

**This changes nothing in your stack.** The aggregator *pushes* (Prometheus Pushgateway +
Loki push API), so no scrape config, no Loki config, and no existing pipeline is touched.

---

## Files

| File | What it is |
|---|---|
| `dashboards/vault-secret-hygiene.json` | 7-panel dashboard. Prometheus for aggregates, Loki for the findings table |
| `../scripts/vault-secret-aggregator.py` | The fold. stdlib only, no dependencies |

⚠️ **Datasource UIDs are inlined and load-bearing.** The JSON ships with the UIDs from the
environment it was built in. Change them to match your own Prometheus and Loki datasources
(Grafana → Connections → Data sources → the UID in the URL), or every panel comes up empty.

Built against Grafana **10.2**, `schemaVersion 38`.

---

## Run it

```bash
# 1. Generate the sample (or point --audit at real audit logs)
cd splunk && python3 generate-sample.py --paths 500 --events 4000 --logins 1000 \
    --out samples/audit.jsonl

# 2. Fold and publish
cd .. && python3 scripts/vault-secret-aggregator.py \
    --audit       splunk/samples/audit.jsonl \
    --inventory   splunk/samples/vault_secret_inventory.csv \
    --pushgateway http://<pushgateway-host>:9091 \
    --loki        http://<loki-host>:3100 \
    --state-file  .state/vault-secret-state.json \
    --print
```

Drop `--pushgateway` and `--loki` to just print the table locally; that path needs nothing
but Python 3.

`--inventory` is **not optional.** A secret nobody has ever read emits no audit event, so it
cannot appear in any log-derived view; it exists only in the baseline inventory. Without it
the headline number is silently missing. The aggregator warns loudly if you omit it.

`--state-file` is the 18-month memory. In production it must be checkpointed; losing it
resets the clock.

---

## Verified

| | ≤30d | ≤90d | ≤180d | ≤365d | ≤540d | never read | rotated but never read |
|---|--:|--:|--:|--:|--:|--:|--:|
| Splunk SPL | 236 | 34 | 6 | 19 | 10 | **195** | **44** |
| This aggregator | 235 | 35 | 6 | 19 | 10 | **195** | **44** |

The one secret that shifts between the 30d and 90d bucket is the clock advancing between
runs; that boundary is genuinely time-sensitive. `never read` and `rotated_but_never_read`
are exact, and they are the two numbers that carry the story.

---

## ⚠️ Known limitation: the findings table accumulates across runs

Findings are pushed to Loki as log lines stamped **now**. That makes them cheap and dodges
`reject_old_samples`, but **every fold appends a fresh copy**. If two folds land inside the
dashboard's time window, every secret shows up twice.

Workarounds, weakest to strongest:

1. **Narrow the dashboard time range** so only the newest fold is in view (`&from=now-4m`).
   Fine for a screenshot, fragile for daily use.
2. **Add a Grafana `groupBy` transformation** on `secret path`, taking `lastNotNull` for every
   other column. Makes the panel idempotent regardless of how many folds are in range.
3. **Stop using a log stream as a table.** The aggregator's state table belongs in
   SQLite/Postgres, queried directly by Grafana. A log stream is an append-only event record;
   using it as current-state storage is a demo convenience, and this duplication is that
   shortcut showing through.

The **aggregate panels are unaffected**: Prometheus gauges are replaced wholesale on each
push (`PUT /metrics/job/...`), so the tiles and histogram always reflect the latest fold only.

---

## Framing

The dashboard carries a **SAMPLE DATA banner** as its first panel. The data is synthetic; the
schema is real. **Do not crop that banner out of a screenshot.**

# Grafana

> Screenshots pending. The previous ones showed panel titles and a banner that no
> longer exist, so they were retired rather than left to document a version that is
> gone. The Splunk walkthroughs carry current screenshots of the equivalent panels.

The same answer without Splunk: identical numbers, identical dataset, no SIEM involved.

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

**Why not just query Loki.** You cannot ask LogQL for "max timestamp per secret path" across
hundreds of thousands of paths; path as a stream label is that many active series and it
kills the index. So the fold happens in a process, and only aggregates cross the wire.
Per-secret detail travels as log lines, never as labels.

**Why findings are stamped "now".** A finding is an observation made today about history.
It also keeps them inside Loki's `reject_old_samples` window, which would otherwise reject
an 18-month-old timestamp outright.

**Nothing in your stack changes.** The aggregator pushes (Prometheus Pushgateway + Loki push
API), so there is no scrape config to edit and no existing pipeline to touch.

## Files

| File | What it is |
|---|---|
| `dashboards/vault-secret-hygiene.json` | 7-panel dashboard. Prometheus for aggregates, Loki for the findings table |
| `scripts/vault-secret-aggregator.py` | The fold. stdlib only, no dependencies |

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

**`--inventory` is not optional.** A secret nobody has ever read leaves no trace in the audit
log, so nothing derived from logs can find it. It exists only in that file. Without it the
headline number is silently wrong. The aggregator warns if you omit it.

**`--state-file` is the eighteen-month memory.** In production it has to be checkpointed to
disk. Lose it and the clock resets to zero.

## ⚠️ The findings table accumulates across runs

Findings are pushed to Loki as log lines stamped now, so **every fold appends a fresh copy**.
Two folds inside the dashboard's time window means every secret appears twice.

The quick fix is a Grafana `groupBy` transformation on secret path taking `lastNotNull` for
the other columns, which makes the panel idempotent. The real fix is to stop using a log
stream as a table: the aggregator's state belongs in SQLite or Postgres, queried directly.

The aggregate panels are unaffected. Prometheus gauges are replaced wholesale on each push,
so the tiles and the histogram always show the latest fold only.

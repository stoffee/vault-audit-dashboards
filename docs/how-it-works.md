# How it works: last-accessed age per secret, from the audit device

Vault's KV metadata API tells you when a secret was *written*. Nothing in Vault readily tells
you when it was last **read**, and "nothing has read this in eighteen months" is the question
an auditor actually asks.

That answer is in the audit log. This document is the method.

---

## 1. The audit device already has every field you need

A live KV v2 read, as emitted by the audit device (trimmed; values are HMAC'd, paths are not):

```json
{
  "time": "2026-08-25T16:00:32.770940252Z",
  "type": "response",
  "auth":    { "entity_id": "<entity-uuid>", "display_name": "<mount>:<ns>:<role>",
               "metadata": { "role": "<role>" }, "policies": ["default","<role>"] },
  "request": { "operation": "read", "path": "secret/data/app-a/key-a",
               "mount_type": "kv", "mount_point": "<ns>/secret/",
               "namespace": { "id": "<ns-id>", "path": "<ns>/" },
               "remote_address": "<client-ip>" },
  "response": { "mount_type": "kv",
                "data": { "data": { "password": "hmac-sha256:42b1…" },
                          "metadata": { "created_time": "hmac-sha256:76bf…", "version": 2 } } }
}
```

| What you need | Field | In the clear? |
|---|---|---|
| WHICH secret | `request.namespace.path` + `request.path` | ✅ plaintext; path is namespace-relative, always concatenate |
| WHAT happened | `request.operation` (`read`/`update`/`list`/`delete`) + `request.mount_type` | ✅ |
| WHEN | `time` | ✅ |
| Did it succeed | `type == "response"` with no `error` | ✅ one response per request; fold responses only |
| WHO | `auth.entity_id`, `auth.display_name`, `auth.metadata.*` | ✅ |
| The secret value | `response.data.data.*` | 🔒 **HMAC'd, never recoverable**, which is exactly what regulated scope needs |

This is the audit *device* schema. It is identical for self-managed Enterprise and HCP; only
the transport differs. Extra top-level `cluster_id` / `hcp_*` keys on HCP entries are
decoration.

---

## 2. Fold it

Group by `(namespace, path)` and keep the max timestamp per operation class:

```
age_d  last_read   last_write  reads   writes  ns/path
  194  2026-02-12  -               1        0  <ns>/secret/data/app-c
  165  2026-03-13  2025-12-05  59204        2  <ns>/secret/data/app-b/config
   84  2026-06-02  2026-06-02      3        2  <ns>/demo-kv/data/app-d/key-d
    0  2026-08-26  2026-02-27  68630        2  <ns>/secret/data/app-a/key-a
never  -           2026-08-20      0      346  <ns>/secret/data/ssl-certificates/cert-a
never  -           2026-08-20      0      365  <ns>/secret/data/ssl-certificates/cert-b
```

- `last_read` is the dormancy answer. `last_write` gives you **rotation age** for free.
- Those last two rows are the finding that lands: TLS-certificate secrets **written 300+
  times each by a renewal job and read by nothing, ever.** Observed on real audit data. No
  tool that inspects secrets one at a time would surface that, because nothing about the
  secret itself looks wrong.
- One extra `group by auth.entity_id` answers "who read this yesterday".

---

## 3. Four rules the fold has to follow

**Fold responses only.** `type == "response"`. One response per request; folding requests too
double-counts everything.

**Only `…/data/…` reads are *use*.** KV v2 puts an API prefix on every path: `data/`,
`metadata/`, `subkeys/`, `delete/`, `undelete/`, `destroy/`. Reads of `metadata/` and
`subkeys/`, and all `list` operations, are **browsing**: the UI, or `vault kv metadata get`.
Fold those in and every secret anyone has ever clicked on looks active. Normalise to the
logical secret path before keying.

**Coalesce the namespace.** Root-namespace events carry `request.namespace.path` as an empty
string, and a bare concatenation yields null, silently dropping every root-namespace secret.
Use `coalesce('request.namespace.path',"") . 'request.path'`.

**Persist the state table.** The aggregator's memory *is* the eighteen-month answer. Losing
it resets the clock to zero.

---

## 4. Why it is a process, not a query

Path cardinality decides the architecture. A large estate has hundreds of thousands of KV v2
secrets, so:

- Secret path as a **Prometheus label** or a **Loki stream label** means that many active
  series. It kills the index and the head block outright.
- A query-time `sum by (path)` over the retention window rescans eighteen months **on every
  dashboard refresh**. At tens to hundreds of millions of audit events per day, that is not
  viable.

So the fold happens once, in a small stateful process, and only aggregates cross the wire:

```
Vault audit device ──► (Fluent Bit / file tail) ──┬──► your SIEM  (unchanged)
                                                  │
                                                  └──► aggregator
                                                        │
              (namespace, path) -> last_read, last_write, reads, writes
                                                        │
                      ┌─────────────────────────────────┴──────────────────┐
                      ▼                                                    ▼
          bucket COUNTS ──► Prometheus              per-secret FINDINGS ──► Loki
          (a handful of series)                     (log lines, cheap)
                      └─────────────────────────────────┬──────────────────┘
                                                        ▼
                                                     Grafana
```

The Splunk-native form of the same decision is a **scheduled search feeding a summary
index** (`collect`). See `R1.4` in `splunk/r1-stale-secrets.spl`. Same idea, Splunk hat.

**Nothing is re-routed.** Fluent Bit tees; your existing SIEM ingest is untouched, at zero
additional ingest cost.

---

## 5. The baseline inventory is not optional

**A secret nobody has ever read emits no audit event.** It cannot appear in any search over
the audit log, because there is nothing to find. It exists only in a one-time path list.

Skip that join and your dashboard shows a clean bill of health while the most important
number, the count of secrets nothing has *ever* touched, is silently missing. There is no
error. The panel just renders.

Build it once with a `vault kv list` / KV metadata walk per mount, then keep it current from
`create` and `delete` audit events. This is the **only** tree walk in the design and it runs
once, which is what makes it acceptable at scale.

---

## 6. Scale

A single-threaded, dependency-free Python fold, measured on a laptop:

| | |
|---|---|
| Throughput | **179,000 events/s** (plain `json.loads`, one core) |
| State table | 262k live paths in **121 MB RSS** |

Against a load of ~1,200 events/s (a hundred million audit events a day), that is over 100×
headroom before anyone needs to reach for Go or Vector.

**Neither CPU nor memory is the constraint.** The constraints are:

1. **History.** Answering "eighteen months" requires eighteen months of audit events to exist
   somewhere. Either replay them once from retained logs, or start the aggregator now and
   let the answer mature.
2. **Baseline.** See §5.

---

## 7. Four ways to get a silently wrong answer

- **Naming too few fields in LogQL.** `| json a="x", b="y"` extracts only what you name.
  Omit a field you then group by and it groups on empty string instead of erroring.
- **Backfilling into Loki.** `reject_old_samples` (default 168h) drops historical
  timestamps. Push findings stamped now instead.
- **Short Splunk retention.** Splunk drops events older than the index freeze period at
  ingest, so the old buckets come back empty and the whole thing looks broken. Check the
  earliest event before trusting any bucket.
- **Treating a log stream as a table.** Every fold appends a fresh copy of the findings, so
  two folds in the window shows every secret twice. Fine for a demo; in production the state
  table belongs in SQLite or Postgres.

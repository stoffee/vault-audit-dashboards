# Splunk

The same answer, in the tool most enterprises already run. If your Vault audit device is
already shipping into Splunk, everything here works over data you have today. No new stack,
no additional ingest.

> ✅ **Verified end to end** on Splunk Cloud **10.5**. Data loaded, searches run, results
> matched independently computed ground truth **exactly**.

---

## Result

`R1.2` run against the 500-path sample, versus the generator's ground truth:

| bucket | Splunk | ground truth | |
|---|--:|--:|:-:|
| ≤ 30 days | 236 | 236 | ✅ |
| ≤ 90 days | 34 | 34 | ✅ |
| ≤ 180 days | 6 | 6 | ✅ |
| ≤ 365 days | 19 | 19 | ✅ |
| ≤ 540 days | 10 | 10 | ✅ |
| **never read** | **195** | **195** | ✅ |
| total | 500 | 500 | ✅ |

Exact on every bucket, not even the ±1 boundary drift the tolerances allowed for.

**`R1.0`** (sanity): 5,327 events spanning the full 540-day window.

**`R1.3`** (the finding that lands): **44 secrets rotated but never read.** The worst was
rotated *the previous day*: 14 writes, zero reads, ever.

---

## Files

| File | What it is |
|---|---|
| `r1-stale-secrets.spl` | The searches. R1.0 sanity, R1.1 fold, R1.2 buckets, R1.3 cleanup list, R1.4 production summary-index form, plus R2/R4/R7/R11 |
| `dashboard-vault-secret-hygiene.xml` | Simple XML dashboard, 6 panels, namespace filter |
| `generate-sample.py` | Builds a realistic audit sample + baseline inventory |
| `samples/` | Generated data; gitignored, regenerate on demand |

```bash
python3 generate-sample.py                                    # 10k paths, 105k events, 139 MB
python3 generate-sample.py --expected                         # print ground truth only
python3 generate-sample.py --paths 500 --events 4000 \
    --logins 1000 --out samples/audit.jsonl                   # 7 MB, the verified variant
```

Deterministic (seed 42), so ground truth is reproducible. **The event schema is real**,
copied field-for-field from a live Vault audit entry. Paths and identities are synthetic.
No credential is present; audit logs only ever carry HMAC'd values.

---

## Load runbook

### 1. Create the index

Settings → Indexes → **New Index**. Name `vault_audit`, type Events, searchable retention
long enough to cover your sample (the shipped one spans 540 days).

> ⚠️ **The index list does not refresh after you save.** It looks like the save failed. It
> didn't; retrying just tells you the index already exists. Confirm it in the index dropdown
> at step 2 instead of creating it twice.

> ⚠️ **Retention trap.** Splunk drops events older than the index freeze period *at ingest*.
> If retention is shorter than your window, the old buckets come back empty and R1 looks
> broken when it isn't. Run `R1.0` before trusting any bucket, or shrink the sample with
> `--window-days N`.

### 2. Upload the events

**Home → "Add data" → Upload.**

> ⚠️ `/en-US/app/search/adddata` **404s on Splunk 10.5**: the classic deep link is gone.
> `/en-US/manager/search/adddata` works. `?input_type=uploadfile` lands on the *modular
> inputs* list, which is the wrong branch. Use the Upload tile.

Select the `.jsonl` → **Next**.

> 🟢 **No `props.conf` needed.** Splunk auto-detects the JSON *and* parses the nanosecond
> ISO-8601 `time` field with zero configuration
> (`2026-07-06T14:26:56.694482586Z` → `7/6/26 2:26:56.694 PM`). An explicit
> `TIME_PREFIX` / `TIME_FORMAT` / `KV_MODE` stanza turned out to be unnecessary.

On **Set Source Type** → **Save As** → `vault:audit`. On **Input Settings** → Index →
`vault_audit`. Review → Submit.

The UI cap is 500 MB, so even the full 139 MB sample loads by hand.

### 3. Upload the baseline inventory as a lookup

Settings → Lookups → **Lookup table files** → **New Lookup Table File**. App `search`,
destination filename `vault_secret_inventory.csv`.

> ⚠️ The deep link `…/data/lookup-table-files/_new` **404s**; go through the listing page.

**This is not optional.** A secret nobody has ever read emits no audit event, so it cannot
appear in any search over the audit index; it exists only in this inventory. Skip it and the
single most important number (195 of 500 here; 3,901 of 10,000 in the full sample) is
silently missing, with no error.

`| inputlookup append=t <file>.csv` resolves the CSV by filename directly, with no lookup
*definition* needed.

### 4. Run the searches

Open `r1-stale-secrets.spl`. **`R1.0` first** (sanity), then `R1.2` (the answer), then `R1.3`
(the finding). Set the time range to **All time**; the default 24h window hides everything.

> ⚠️ **`coalesce` on the namespace is required.** Root-namespace events carry
> `request.namespace.path` as an empty string, and a bare concat yields null, silently
> dropping every root-namespace secret. Use
> `eval secret = coalesce('request.namespace.path',"") . 'request.path'`.

### 5. Import the dashboard

Dashboards → Create New Dashboard → Classic → Source, then paste
`dashboard-vault-secret-hygiene.xml`.

> ⚠️ The root element must be `<form version="1.1" …>`. Without the `version` attribute
> Splunk's validator blocks the save.

---

## Against your own estate

1. **Your index and sourcetype names.** Whatever ships your audit device into Splunk already
   set them. Only the first line of each search changes. Don't guess; ask whoever owns the
   pipeline.
2. **Your audit retention depth.** This decides whether R1 answers "18 months" on day one or
   accumulates toward it.
3. **The baseline inventory.** A one-time KV metadata walk, which needs a read-only policy.
4. **`R1.1` vs `R1.4`.** The simple search rescans the whole retention window on every run.
   At enterprise volume that is not viable; production means the scheduled search into a
   summary index. Know which one you are showing.
5. **`R2` / `R4` / `R7` / `R11` are written but unrun.** R1 was the one everything hung on;
   the rest are cheap once someone runs them.

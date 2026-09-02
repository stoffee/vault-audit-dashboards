# Splunk

The same answer, in the tool most enterprises already run. If your Vault audit device is
already shipping into Splunk, everything here works over data you have today. No new stack,
no additional ingest.

> ✅ **Verified end to end** on Splunk Cloud **10.5**. Data loaded, searches run, results
> matched independently computed ground truth **exactly**.

---

## Files

| File | What it is |
|---|---|
| `r1-stale-secrets.spl` | The searches. R1.0 sanity, R1.1 fold, R1.2 buckets, R1.3 cleanup list, R1.4 production summary-index form, plus R2/R4/R7/R11 |
| `dashboard-vault-secret-hygiene.xml` | Simple XML dashboard: SAMPLE DATA banner, 3 headline tiles, and 4 R1/R2/R7/R11 panels, with a namespace filter |
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

> ⚠️ **Retention trap.** Splunk drops events older than the index freeze period *at ingest*.
> If retention is shorter than your window, the old buckets come back empty and R1 looks
> broken when it isn't. Run `R1.0` before trusting any bucket, or shrink the sample with
> `--window-days N`.

### 2. Upload the events

**Home → "Add data" → Upload.** Select the `.jsonl` → **Next**. On **Set Source Type** →
**Save As** → `vault:audit`. On **Input Settings** → Index → `vault_audit`. Review → Submit.

No `props.conf` is needed: Splunk auto-detects the JSON and parses the nanosecond ISO-8601
`time` field with no configuration.

### 3. Upload the inventory CSV

Settings → Lookups → **Lookup table files** → **New Lookup Table File**. App `search`,
destination filename `vault_secret_inventory.csv`.

**Do not skip this.** A secret that nobody has ever read leaves no trace in the audit log,
so no search can find it. This CSV is the only place it exists. Without it the dashboard
still renders, still looks fine, and quietly leaves out the biggest number on the page: 195
of the 500 secrets in the small sample have never been read.

That is it: upload the file. Splunk normally also wants a *lookup definition* pointing at an
uploaded file, but the searches here reference the CSV by filename, so you don't need one.

### 4. Run the searches

Open `r1-stale-secrets.spl`. **`R1.0` first** (sanity), then `R1.2` (the answer), then `R1.3`
(the finding). Set the time range to **All time**; the default 24h window hides everything.

> ⚠️ **`coalesce` on the namespace is required.** Root-namespace events carry
> `request.namespace.path` as an empty string, and a bare concat yields null, silently
> dropping every root-namespace secret. Use
> `eval secret = coalesce('request.namespace.path',"") . 'request.path'`.

### 5. Import the dashboard

Dashboards → Create New Dashboard → Classic → Source, then paste
`dashboard-vault-secret-hygiene.xml`. The root element must keep its `version` attribute
(`<form version="1.1" …>`) or the validator blocks the save.

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
5. **`R2` / `R4` / `R7` / `R11` are written but never run.** Only the R1 searches have been
   tested end to end. The rest are straightforward, but treat them as drafts.

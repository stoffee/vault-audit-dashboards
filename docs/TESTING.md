# Testing

How to know a dashboard is right, rather than merely rendering.

## The one rule

**A panel that renders is not a panel that works.**

Every bug found in this project so far produced a dashboard that looked completely healthy
while being wrong. A wildcard that dropped 40% of events. A coalesce that showed hashes
instead of error messages. A `stats BY` that could never return a row. None of them threw
an error, and none of them left an empty panel that would make you suspicious.

So test with numbers you can check, and check columns as well as rows.

## Check these four things first

Run these against your own data before trusting any panel. Each one catches a bug class
that has actually shipped here.

**1. Root-namespace events must survive.** In a real audit event the root namespace is
`{"id": "root"}` with no `path` key. If the root row shows `distinct_paths = 0`, a path
concat somewhere is dropping every root-namespace event.

```
index=vault_audit type=response
| eval secret = coalesce('request.namespace.path',"") . 'request.path'
| eval ns = if(isnull('request.namespace.path') OR 'request.namespace.path'=="","ROOT",'request.namespace.path')
| stats count, dc(secret) AS distinct_paths BY ns
```

**2. Error text must be readable.** If this returns `hmac-sha256:...` then a coalesce is
checking `response.data.error` first. Vault HMACs that field, so it is always populated and
always useless; the human-readable reason is in the top-level `error`.

```
index=vault_audit | eval err = coalesce('error','response.data.error')
| where isnotnull(err) AND err!="" | stats count BY err
```

**3. Volume work must count both event types.** Vault writes a `request` entry and a
`response` entry, roughly 1:1, and your SIEM bills for both. A volume number built from
responses only is half the truth.

```
index=vault_audit | stats count BY type
```

**4. Denials need both signals.** `auth.policy_results.allowed` is a clean boolean, but it
is only set once policy evaluation runs. An invalid token fails before that and has no
`policy_results` at all. Measured on one real capture: the boolean caught 30 denials while
46 events carried error text.

```
index=vault_audit
| eval denied = if('auth.policy_results.allowed'=="false",1,0)
| eval err = coalesce('error','response.data.error')
| stats count AS total, sum(denied) AS by_boolean,
        sum(eval(if(isnotnull(err) AND err!="",1,0))) AS by_error_text
```

## Watch for silently dropped columns

Single quotes are a field reference in `eval` and `where`, and a literal string everywhere
else. In a transforming command they match nothing, and the column vanishes with no error:

```
| stats count BY 'request.operation'    <- 0 rows
| table 'request.remote_address'        <- column silently absent
| stats count BY request.operation      <- correct
```

The worst case is a table that still returns rows while dropping half its columns. So when
you check a panel, **count its columns, not just its rows.**

## Verifying the ingest itself

Timestamp parsing is load-bearing. Every hygiene number is an **age**, so a wrong
`TIME_FORMAT` shifts every bucket without erroring. Confirm the ingested time range matches
your source before trusting anything.

You can read event counts and time ranges straight from bucket metadata, without logging in:

```bash
python3 -c "
import glob, datetime as dt
for f in glob.glob('\$SPLUNK_HOME/var/lib/splunk/<index>/db/*/Hosts.data'):
    for i, l in enumerate(open(f)):
        if i == 1:
            p = l.split(chr(9))
            print(p[2], 'events',
                  dt.datetime.fromtimestamp(int(p[3]), dt.UTC),
                  '->', dt.datetime.fromtimestamp(int(p[4]), dt.UTC))
"
```

Glob `db/*/`, not `hot_v1_*`: hot buckets roll to warm on restart, and a hot-only glob
reports zero on a perfectly healthy index.

⚠️ **Never modify a file a `monitor://` input is watching.** Sorting or dedup'ing it in
place changes its CRC, Splunk re-reads the whole file, and you get duplicates. The symptom
is an event count that is a clean multiple of your line count. Write a new filename and
repoint the input instead.

## Age buckets drift, and that is correct

Last-read ages are measured from *now*, so a secret last read almost exactly 30 days ago
moves from the `<=30d` bucket into `<=90d` as the day passes. Their **sum is stable**; the
split is not. Do not treat a moved boundary as a regression.

## Known gaps, stated plainly

- **`tls-noise.spl` does not read the audit log.** TLS handshakes fail before Vault writes
  an audit entry, so it needs Vault *server* logs. Pointed at the audit index it renders a
  permanently empty dashboard with no error. It is also the only file here that has never
  been executed against data.
- **Policy trending needs policy-management events.** An audit stream with no policy writes
  in the window renders those panels empty, correctly.
- **Namespace panels need Vault Enterprise.** Community edition has no namespaces, so every
  event lands in root.
- **Scheduled rollup searches return nothing when run ad hoc.** They are written for an
  hourly window (`earliest=-1h@h latest=@h`). Empty outside that window is expected.

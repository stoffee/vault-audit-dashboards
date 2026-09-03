# vault_audit_hygiene (Splunk app)

Drop-in Splunk app: dashboards, index definitions, sourcetype parsing, and the
read-only auditor role. Configuration only, no UI click-path required.

## Install

```bash
cp -r vault_audit_hygiene $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart
```

Then copy `default/inputs.conf` to `local/inputs.conf`, set your audit log path, and
set `disabled = false`.

## What is in here

| File | Purpose |
|---|---|
| `default/indexes.conf` | `vault_audit`, and `vault_summary` for the rollup |
| `default/props.conf` | `vault:audit` sourcetype. **Timestamp parsing is load-bearing**, every hygiene number is an age, so a bad parse shifts every bucket without erroring |
| `default/authorize.conf` | the `vault_auditor` read-only role |
| `default/transforms.conf` | the baseline path inventory lookup definition |
| `default/data/ui/views/` | three dashboards |

## The auditor role

`vault_auditor` is built from nothing rather than by importing Splunk's stock `user`
role. That is deliberate: `user` ships with `srchIndexesAllowed = *`, so inheriting it
would grant every index on the deployment.

When you assign the role to a user, assign **only** this role. Leaving `user` checked
re-grants `*` and silently defeats the scoping.

`input_file` is deliberately not granted. With it, a "read-only" user can `| inputcsv`
arbitrary files off the Splunk server's disk.

`authorize.conf` also carries a commented `srchFilter` for excluding a regulated
namespace. Audit logs contain no secret values, but path names may themselves be in
scope. That is a compliance decision, so it ships switched off.

## The lookup

`lookups/vault_secret_inventory.csv` is **not** shipped, because it is generated and
site-specific. Without it, secrets nobody has ever read are invisible: they emit no
audit event, so no search over the audit index can find them.

Generate it from a one-time KV metadata walk with columns `secret,namespace,mount`,
and place it in `lookups/`. See `docs/how-it-works.md` in the repository.

# Trace a transaction

> A workload read a secret. Which workload, from where, under which policy, and what else
> has it been touching?

This is a different pipeline from the other two Grafana dashboards. Secret Hygiene and
Lease Visibility both go through `vault-secret-aggregator.py`, which folds the audit stream
into aggregates before anything crosses the wire. Transaction Trace instead reads **raw
audit JSON pushed straight into Loki**, one line per event, and does the pivot at query
time. See **Architecture: the raw-audit-to-Loki pipeline** in `grafana/README.md` before
deploying this one — it needs a shipper, not the aggregator.

## The pivot: workload identity

The trace keys on **who the client is**, not a hostname or IP, because in a containerised
estate those are meaningless by the time you investigate. The dashboard's `workload` label
is whatever your shipper extracts from the audit event's `display_name` (or equivalent) at
ingest time — see the README for what that extraction has to do.

⚠️ **If the "Select Workload" dropdown collapses to one value or `unknown`, your auth mount
is not writing identity metadata**, or the shipper isn't parsing it out. That's a mount
configuration or shipper-config question, not a dashboard fault.

## Direction 1: who reads this secret

Leave **Select Workload** as `All` and put the path in **Secret path filter**, e.g.
`secret/data/prod/db-creds`. The **SECRET PATH**, **IDENTITY**, **RESULT** stat panels and
the **Recent Transactions** table all scope to that filter.

⚠️ **The WHO / WHAT stat tiles and the Activity Timeline do not honor the path filter.**
They're built on `count_over_time(...) | __stream_workload__`, a label-stream extraction
that runs before the path (which lives inside the JSON body, not a label) is parsed. Those
three panels answer "what has this workload been doing," a workload-scoped question, even
when you've set a path filter. Use **Recent Transactions** for the path-scoped answer.

## Direction 2: what does this workload touch

Leave **Secret path filter** as `.*` and pick the identity from **Select Workload**. The
**Recent Transactions** table then reads as a timeline: operation, path, filtered to that
one workload. **Activity Timeline** and the **Access by Workload** breakdown chart show the
same slice over time and against the rest of the estate.

## Reading the result

**A workload touching far more paths than you expected** is over-broad policy. The
**POLICIES** tile shows which policy allowed it.

**A path touched by many unrelated workloads** (set the path filter, leave Workload as
`All`, scan **Recent Transactions**) is a shared credential. Rotating it is a coordinated
change.

**RESULT** reads `FAILED` on any non-empty `error` field, `SUCCESS` otherwise. This is a
single boolean-ish read of the `error` string, not the OR-of-two-signals logic the Splunk
transaction trace uses (`auth.policy_results.allowed` OR non-empty `error`, see
[Splunk's version of this scenario](../../splunk/scenarios/02-trace-a-transaction.md#reading-the-result)
for why one signal alone under-counts). If you need that finer denial/auth-failure split on
the Grafana side, it isn't built here yet — the Secret Hygiene dashboard's separate
**Denied requests** panel ([scenario](02-denied-requests.md)) is namespace-scoped, not
per-workload, and doesn't fill this gap.

## What it cannot tell you

The audit log records that a workload read a secret. It does not record what the workload
then did with it. If a credential is suspected leaked, this scopes exposure; it does not
prove or disprove misuse.

## Status

Deployed and running against a live HCP Vault + Nomad estate (the dashboard this was ported
from), but the `workload` label and the `path_filter` variable added here to generalize it
beyond that one environment have **not** been run against real Grafana yet. Import it,
point it at a real Loki instance with the field mapping below satisfied, and verify before
trusting a number from it.

## Field mapping

| Panel expects | Comes from (in the audit event JSON) |
|---|---|
| `workload` (Loki label) | Whatever your shipper derives from `auth.display_name` — see README |
| `operation` | `request.operation` |
| `path` | `request.path` |
| `display_name` | `auth.display_name` |
| `remote_address` | `request.remote_address` |
| `policies` | `auth.policies` (or `auth.token_policies`) |
| `error` | top-level `error` on the response event |
| `event_type` | `request` vs `response` — the dashboard reads `response` only |

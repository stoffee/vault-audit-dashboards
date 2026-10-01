# LogScale

For estates where the audit stream already lands in CrowdStrike LogScale / NG-SIEM
instead of Splunk or Loki, the query runs where the data already is, no shipper or
aggregator needed.

⚠️ **Query syntax not yet run against a live LogScale instance.** The field-level logic
is accurate to a live Vault audit device; the LogScale query syntax may need a small
adjustment for your environment. Validate field names and query behavior against one
real audit entry before trusting a result. Splunk and Grafana in this repo carry a
"tested against live data" status; this directory does not, yet.

## What is here

| Path | What it is |
|---|---|
| `queries/denied-request-trace.lql` | Chronological denial trace plus a candidate-policy rollup |
| `scenarios/01-which-policy-denied-this.md` | Troubleshooting guide: narrow the candidate policies with the query, pin one down with a policy diff, confirm with a live lookup if needed |

## Why this exists, and what it deliberately does not try to do

A permission-denied audit event lists every policy that was in play, not the one that
lacked the capability (see the scenario doc for the field shapes). No query against
historical audit data, LogScale, Splunk, or Loki, can turn that into true single-policy
attribution. These queries narrow the field; they do not finish the job on their own.
The scenario doc pairs the query with a policy-content diff, and a live
`vault read identity/entity/id/...` lookup for confirming current state.

## Worth confirming on your own cluster

- Whether a Sentinel RGP/EGP denial produces a different `error` string than an ACL
  denial.
- How `auth.external_namespace_policies` renders under your audit device's HMAC
  settings, and whether it and `auth.identity_policies` both populate correctly when a
  single token carries both a same-namespace and a cross-namespace grant at once.

See the sanity-check query (query 3) in `denied-request-trace.lql` as a starting point.

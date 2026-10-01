# LogScale

For estates where the audit stream already lands in CrowdStrike LogScale / NG-SIEM
instead of Splunk or Loki - the query runs where the data already is, no shipper or
aggregator needed.

⚠️ **UNVERIFIED.** Nobody maintaining this repo has a LogScale instance to test against.
Every query here is the field-level logic from a verified-live Vault audit device,
written in LogScale's query language, not tested LogScale syntax. Validate field names
and query behavior against one real audit entry before trusting a result. Splunk and
Grafana in this repo carry the "tested against live data" status; this directory does
not, yet.

## What is here

| Path | What it is |
|---|---|
| `queries/denied-request-trace.lql` | Chronological denial trace plus a candidate-policy rollup |
| `scenarios/01-which-policy-denied-this.md` | The two-part workflow: narrow with the query, pin down with a live entity/token lookup |

## Why this exists, and what it deliberately does not try to do

A permission-denied audit event lists every policy attached to the token, not the one
that lacked the capability (see the scenario doc for a verified example). No query
against historical audit data - LogScale, Splunk, or Loki - can turn that into true
single-policy attribution. These queries narrow the field; they do not claim to finish
the job. The scenario doc pairs the query with a live `vault read identity/entity/id/...`
lookup for the part only a live Vault API call can answer.

## Open, unverified for your cluster

- Does a Sentinel RGP/EGP denial produce a different `error` string than an ACL denial?
- Does the audit event's `auth` block carry group-derived or cross-namespace
  (`external_namespace_policies`) grants, or only the token's own `token_policies`?

Capture one real denied-request audit entry of each kind before relying on either
query to cover those cases. See the sanity-check query (query 3) in
`denied-request-trace.lql` as a starting point.

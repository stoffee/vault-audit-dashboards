# Trace a transaction

> A workload read a secret. Which workload, from where, under which policy, and what else
> has it been touching?

This runs in both directions: from a secret out to its consumers, and from a workload in
to everything it touched.

## The pivot: workload identity

The trace keys on **who the client is**, not on a hostname or an IP, because in a
containerised estate those are meaningless by the time you investigate.

| Auth method | Identity comes from | Renders as |
|---|---|---|
| Kubernetes | `auth.metadata.service_account_name`, plus cluster and namespace | `eks-prod-135/ordering/sa-ordering` |
| CI pipelines | `auth.metadata.pipeline_id` or `auth.display_name` | `gitlab-identity:pipeline-384967` |
| Everything else | `auth.display_name` | varies by mount |

⚠️ **If every row collapses to one value, your auth mount is not writing identity
metadata.** That is a mount configuration question, not a dashboard fault. The Kubernetes
auth method populates service account metadata; several others populate nothing useful.

Cluster and namespace are part of the key deliberately. `sa-api` exists in hundreds of
clusters and they are not the same workload; collapsing them turns a trace into a
coincidence.

## Direction 1: who reads this secret

`Vault Transaction Trace` -> put the path in **Secret path**, leave **Workload** as `*`.

The **Who reads this secret** panel lists every distinct consumer with first-seen and
last-seen. This is the panel to use before rotating anything: it tells you how many things
you are about to break.

## Direction 2: what does this workload touch

![Recent transactions](../../docs/images/splunk-trace-transactions.jpg)

Leave **Secret path** as `*` and put the identity in **Workload**. Partial matches work,
so `sa-ordering` finds it across every cluster.

The **Recent Transactions** table then reads as a timeline: when, what operation, which
path, the result, and the source IP.

## Reading the result

**A workload touching far more paths than you expected** is over-broad policy. The
`policies` tile shows which policy allowed it, which is where to go and narrow.

**A path touched by many unrelated workloads** is a shared credential. Rotating it is a
coordinated change.

**Failures and denials** are on the same page. Detection uses
`auth.policy_results.allowed`, a boolean set once policy evaluation runs, with the
human-readable reason alongside it.

⚠️ **Neither denial signal is complete on its own, and this is measured, not assumed.** On
a real capture of 348 responses, the boolean flagged 30 denials while 46 events carried
error text. The extra 16 were auth failures such as an invalid token, which fail *before*
policy evaluation and therefore have no `policy_results` at all. The panel ORs both.

## What it cannot tell you

The audit log records that a workload read a secret. It does not record what the workload
then did with it. If a credential is suspected leaked, this scopes exposure, it does not
prove or disprove misuse.

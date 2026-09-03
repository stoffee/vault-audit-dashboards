# Find stale secrets

> How many credentials has nothing read in eighteen months?

This is the cleanup list, and the number an auditor asks for.

## Before you trust any number here: the baseline inventory

**A secret nobody has ever read emits no audit event.** It cannot appear in any search over
the audit index. It exists only in a separate list of every path in the estate.

Without `vault_secret_inventory.csv` loaded as a lookup, the "never read" count is not
wrong in an obvious way. It is silently lower than the truth, with no error and no empty
panel. That is the single most important number on the dashboard, and it is the one that
vanishes quietly.

Build the inventory from a one-time KV metadata walk: `vault secrets list`, then recurse
`vault kv metadata list` per mount, writing `secret,namespace,mount`.

## Steps

1. `Vault Audit Hygiene` -> **Vault Secret Hygiene**
2. Pick a namespace, or leave `All namespaces`
3. Read the three tiles, then the age distribution, then the cleanup table

## Reading the three tiles

| Tile | Means | Action |
|---|---|---|
| **Secrets nobody has ever read** | In the inventory, zero read events across the whole window | Candidates for deletion. Confirm against the inventory's age first |
| **Not read in over a year** | Last read is older than 365 days | The eighteen-month question lives here. Widen the window if your retention allows |
| **Rotated but never read** | Something is writing it; nothing consumes it | The most actionable of the three, see below |

## The finding that lands

![Cleanup candidates](../../docs/images/splunk-hygiene-cleanup.jpg)

**Rotated but never read** is the one to lead with. Every row is a credential a rotation
job is faithfully maintaining, on schedule, that no workload has ever consumed. It is pure
cost and pure risk surface, and it is invisible to every tool that looks at rotation
compliance, because from a rotation tool's point of view those secrets are perfectly
healthy.

## Sanity checks before quoting a number

**Total must equal your inventory row count.**

```
| inputlookup vault_secret_inventory.csv | stats count
```

If the dashboard total is lower, the join is dropping rows. If it is zero, the lookup did
not load and every hygiene number on the page is understated.

**Age buckets drift, and that is correct.** Ages are measured from *now*, so a secret last
read almost exactly 30 days ago moves from `<=30d` to `<=90d` as the day passes. The sum is
stable, the split is not. Do not treat a moved boundary as a regression.

## The caveat that can invalidate the whole answer

⚠️ **Caching clients.** If your workloads use the External Secrets Operator, the Vault
Secrets Operator, or any sidecar that caches, a secret is read once per version and then
served from cache. An actively used credential can look untouched for months.

This does not make the dashboard wrong, but it changes what the number means: it is
"nothing has *fetched* this from Vault", not "nothing is *using* it". Establish how much of
your estate caches before putting this number in front of an auditor. A large operator
publicly documents hitting exactly this.

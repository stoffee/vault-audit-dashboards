# Troubleshooting guide: which policy denied this?

> A token got "permission denied." It has several policies, maybe RGP/EGP, maybe a
> cross-namespace group grant. This is how to narrow it down and pin it down.

⚠️ **STATUS: NOT YET TESTED AGAINST A LIVE LOGSCALE INSTANCE OR A NAMESPACED VAULT
CLUSTER.** The query (`denied-request-trace.lql`) is the right logic, written against a
verified real Vault audit-log field shape, but its LogScale syntax has not been run
anywhere, because no LogScale instance was available to test against (Falcon LogScale
requires a product license key, which takes 1-2 business days to obtain and wasn't in
hand when this was written). The Vault-side steps below (`vault policy read`, `vault
read identity/entity/id/...`, `vault token lookup`) ARE tested, against a real throwaway
Vault audit log - see the verified example inline. Run the query once against a real
audit entry before trusting its output; the field logic should be right, the exact
LogScale syntax might need a small fix.

## The short version

1. **Run the trace** ([`denied-request-trace.lql`](../queries/denied-request-trace.lql),
   query 1) filtered to the denied path or the identity. Get the timestamp, the
   candidate policy list (`auth.policies`), and the `entity_id`.
2. **Read each candidate policy's content** (`vault policy read <name>`) and check it
   against the path and operation that was denied. Usually this finds it.
3. **If the candidate list looks incomplete** (a cross-namespace grant might not be in
   it, see below), look up the entity directly: `vault read
   identity/entity/id/<entity_id>`.
4. **If the token is still live**, `vault token lookup`, `vault token capabilities
   <path>`, and `-output-policy` are faster and more direct than any of the above.
5. **If it might be a Sentinel RGP/EGP denial, not ACL** - none of this guide
   distinguishes the two yet. Capture the raw `error` string and treat it as a new data
   point, not a known case.

Detail on each step, and why, below.

## Why this takes two tools, not one query

A Vault ACL denial in the audit log looks like this (verified against a real throwaway
Vault, 2026-10-01):

```json
{"error": "1 error occurred:\n\t* permission denied\n",
 "auth": {"policies": ["default", "narrow"], "token_policies": ["default", "narrow"]}}
```

It lists **every policy on the token**, not the one that lacked the capability. With one
non-default policy, the candidate list *is* the answer. With three or four, it's a
shortlist. That's the hard limit of what any audit-log-based view can ever show, dashboard
or otherwise: the audit log names the policies, not the line.

**Also verified (2026-10-01, same test):** a group-derived policy *does* land in the
audit log, not just the token's own directly-attached policies. An entity in a group
carrying `tenant-policy`, logging in through an aliased auth method, produced this on
every request, success or denial:

```json
"auth": {"policies": ["default", "narrow", "tenant-policy"],
         "token_policies": ["default", "narrow"],
         "identity_policies": ["tenant-policy"],
         "entity_id": "6eea2892-..."}
```

`policies` is the full merged set used for the actual authorization decision.
`identity_policies` isolates the group-derived ones. So for same-namespace,
group-membership-derived policies, **step 1 alone already has the answer** - no need to
go further just to discover that a group granted it.

**Still unverified:** this test used OSS Vault, root namespace only - no Enterprise
license available to test namespaces locally. The specific cross-namespace shape (an
external group in one namespace granting a policy through membership in an internal
group inside a different namespace, surfaced on a token as `external_namespace_policies`)
is Enterprise-only and this test could not exercise it. Whether it shows up in `auth`
the same way `identity_policies` does is unconfirmed - check this first on a real
namespaced cluster before assuming step 1 covers the cross-namespace case too. Also
unverified: whether a Sentinel RGP/EGP denial produces a different `error` shape than
ACL.

## Step 1: Run the trace

[`denied-request-trace.lql`](../queries/denied-request-trace.lql), query 1, gives a
chronological denial trace: search by path or by identity and get every denial in time
order, with the full candidate-policy list, the namespace, and the identity
(`auth.display_name`, `auth.entity_id`) on each row.

Query 2 rolls that into one row per path: how many denials, which policies kept showing
up, when the last one happened. Useful for triage, which paths are worth investigating
at all, not for a single-incident root cause.

**Output of this step:** a candidate policy list (confirmed to include same-namespace
group-derived policies via `identity_policies`, not just `token_policies`), a
namespace, and an `entity_id`.

## Step 2: Diff the candidates against what the request needed

This step is offline and deterministic - it does not require the original token to
still be live, because it only reads policy *content*, not token state:

```bash
vault policy read <candidate-policy-name>
```

Check each policy from step 1's `auth.policies` against the denied path and operation.
The one lacking a matching `path` block, or whose capabilities don't include the
operation attempted, is the actual culprit - as long as the policy's content hasn't
changed since the denial. If it has, this step only tells you what's true *now*, not
what was true at the time, and that gap should be called out explicitly when reporting
the finding.

## Step 3: If the candidate list might be incomplete, go live

Step 2 assumes step 1's `auth.policies` already named every policy in play. That's
**confirmed** for same-namespace, group-membership-derived policies (tested
2026-10-01). It is **not yet confirmed** for the cross-namespace case - if that's a
live possibility for the estate in question, don't trust step 1's list as complete until
it's checked.

The audit log HMACs the token and its accessor (`auth.client_token`, `auth.accessor`),
not reversible, by design, so you cannot take what's in LogScale and feed it into
`vault token lookup -accessor` to pull up the live token. **`entity_id` is cleartext**,
though, and entities are persistent Vault objects, so this still works after the
original token has expired:

```bash
vault read identity/entity/id/<entity_id>
```

This returns the entity's **current** group memberships (not necessarily what they were
at denial time, same caveat as step 2). Check whether any of them is an **external
group**: a root-namespace external group that is a member of an internal group inside a
tenant namespace, carrying a tenant policy, is a known shape in multi-tenant
namespace-per-tenant designs. That shape specifically needs confirming it even surfaces
in the audit log at all; this entity lookup is the fallback if it doesn't.

## Step 4: If the token is still live, these are faster

Run by whoever holds the token, since the token itself never appears in cleartext and is
not reconstructable from the audit log alone:

```bash
vault token lookup                      # shows identity_policies, external_namespace_policies
vault token capabilities <path>         # direct can-it-or-can't-it, no guessing
VAULT_LOG_LEVEL=trace vault <command> -output-policy   # generates the policy the command needed; diff against what's attached
```

## Step 5: Sentinel RGP/EGP

None of the above distinguishes an ACL denial from a Sentinel one. If a real denial of
that kind turns up, capture the raw `error` string and feed it back - that's the one
piece this guide cannot currently promise to handle, because there's no Enterprise
cluster with Sentinel enabled to verify it against.

## What this cannot tell you

Whether the denial was a misconfiguration or someone probing. It scopes which policies
were in play and who the identity was; it does not establish intent. And if the token
has since been revoked and its entity deleted, step 3 has nothing left to look up.
Capture the entity_id while the trail is fresh.

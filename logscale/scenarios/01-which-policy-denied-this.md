# Troubleshooting guide: which policy denied this?

> A token got "permission denied." It has several policies, maybe RGP/EGP, maybe a
> cross-namespace group grant. This is how to narrow it down and pin it down.

⚠️ **Before relying on this guide, confirm the LogScale query syntax and field names
against one real denied-request audit entry in your own environment.** The field logic
below is accurate to how Vault's audit log is structured; the exact LogScale query
syntax may need a small adjustment for your repo configuration.

## The short version

1. **Run the trace** ([`denied-request-trace.lql`](../queries/denied-request-trace.lql),
   query 1) filtered to the denied path or the identity. Get the timestamp, the
   candidate policy list (`auth.policies` plus `auth.external_namespace_policies` for
   the denied request's namespace ID, see below), and the `entity_id`.
2. **Read each candidate policy's content** (`vault policy read <name>`) and check it
   against the path and operation that was denied. Usually this finds it.
3. **If a cross-namespace grant is in play but the namespace ID isn't a key in
   `external_namespace_policies`,** that's the answer: the identity has no grant in the
   namespace where the denial happened, even if it has one elsewhere.
4. **If the token is still live**, `vault token lookup`, `vault token capabilities
   <path>`, and `-output-policy` are faster and more direct than any of the above.
5. **If it might be a Sentinel RGP/EGP denial, not ACL:** this guide doesn't
   distinguish the two. Capture the raw `error` string and treat it as a new data point.

Detail on each step, and why, below.

## Why this takes two tools, not one query

A Vault ACL denial in the audit log looks like this:

```json
{"error": "1 error occurred:\n\t* permission denied\n",
 "auth": {"policies": ["default", "narrow"], "token_policies": ["default", "narrow"],
          "policy_results": {"allowed": false}}}
```

It lists **every policy on the token**, not the one that lacked the capability, and
`policy_results` on a denial carries nothing but `allowed: false`. Vault does not log
which policies it evaluated or which one failed. With one non-default policy, the
candidate list *is* the answer. With three or four, it's a shortlist. That's the hard
limit of what any audit-log-based view can ever show, dashboard or otherwise: the audit
log names the policies, not the line.

On an **allowed** request, by contrast, `policy_results.granting_policies` names the
exact policy that granted it, including its namespace path:

```json
"auth": {"policies": ["default"],
         "policy_results": {"allowed": true,
           "granting_policies": [{"name": "tenant-admin", "namespace_id": "o54YU",
                                   "namespace_path": "tenant-a/", "type": "acl"}]}}
```

That's real attribution, for the case you're usually not investigating.

A group-derived policy, same namespace as the request, also lands in the audit log, not
just the token's own directly-attached policies. An entity in a group carrying
`tenant-policy`, logging in through an aliased auth method, produces this on every
request, success or denial:

```json
"auth": {"policies": ["default", "narrow", "tenant-policy"],
         "token_policies": ["default", "narrow"],
         "identity_policies": ["tenant-policy"],
         "entity_id": "6eea2892-..."}
```

`policies` is the full merged set used for the actual authorization decision.
`identity_policies` isolates the group-derived ones. So for same-namespace,
group-membership-derived policies, **step 1 alone already has the answer**: no need to
go further just to discover that a group granted it.

**Cross-namespace grants are different, and this is the one that matters most for a
namespace-per-tenant design.** A root-namespace external group that's a member of an
internal group inside a tenant namespace, carrying a tenant policy, does **not** show up
in `auth.policies` or `auth.identity_policies` at all. It only appears in
`auth.external_namespace_policies`, a map keyed by **namespace ID**, not path:

```json
"auth": {"policies": ["default"], "identity_policies": null,
         "external_namespace_policies": {"o54YU": ["tenant-admin"]},
         "policy_results": {"allowed": false}}
```

That's a denial in a namespace where the grant exists but the path was out of scope. In
a namespace where the grant does **not** exist, the auth block looks the same except
`external_namespace_policies` doesn't contain that namespace's ID at all, which is
itself the answer: no grant there, even if the identity has one elsewhere. A query that
only checks `auth.policies` reads this token as default-only in every namespace, which
is a false negative, not an empty result, and the wrong conclusion to hand someone
mid-investigation.

Two things worth confirming on your own cluster before relying on this: how
`external_namespace_policies` renders under your audit device's HMAC settings, and
whether the same-namespace (`identity_policies`) and cross-namespace
(`external_namespace_policies`) fields both populate correctly when a single token
carries both kinds of grant at once. Also still open: whether a Sentinel RGP/EGP denial
produces a different `error` shape than ACL.

## Step 1: Run the trace

[`denied-request-trace.lql`](../queries/denied-request-trace.lql), query 1, gives a
chronological denial trace: search by path or by identity and get every denial in time
order, with the full candidate-policy list, the namespace, and the identity
(`auth.display_name`, `auth.entity_id`) on each row.

Query 2 rolls that into one row per path: how many denials, which policies kept showing
up, when the last one happened. Useful for triage, which paths are worth investigating
at all, not for a single-incident root cause.

**Output of this step:** a candidate policy list built from two fields, not one:
`auth.policies` (token-attached plus same-namespace group-derived, via
`identity_policies`) and `auth.external_namespace_policies[request.namespace.id]`
(cross-namespace group grants, keyed by namespace ID). A namespace, and an `entity_id`.

## Step 2: Diff the candidates against what the request needed

This step is offline and deterministic: it does not require the original token to
still be live, because it only reads policy *content*, not token state:

```bash
vault policy read <candidate-policy-name>
```

Check each policy from step 1's combined candidate set against the denied path and
operation, in the namespace it actually applies to (a cross-namespace policy lives in
the tenant namespace, not the token's root namespace, so read it there). The one lacking
a matching `path` block, or whose capabilities don't include the operation attempted, is
the actual culprit, as long as the policy's content hasn't changed since the denial. If
it has, this step only tells you what's true *now*, not what was true at the time, and
that gap should be called out explicitly when reporting the finding.

If `request.namespace.id` from step 1 isn't a key in `external_namespace_policies` at
all, stop here: that's the finding. The identity has no cross-namespace grant in the
namespace where the denial happened, even if it has one elsewhere.

## Step 3: Confirm current state with a live lookup

Step 1's candidate set is a point-in-time snapshot. If policies or group membership have
changed since the denial, or you want to double-check against current state rather than
what the audit log captured, `entity_id` lets you do that without needing the original
token. The audit log HMACs the token and its accessor (`auth.client_token`,
`auth.accessor`), not reversible, by design, so you cannot take what's in LogScale and
feed it into `vault token lookup -accessor` to pull up the live token. **`entity_id` is
cleartext**, though, and entities are persistent Vault objects, so this still works
after the original token has expired:

```bash
vault read identity/entity/id/<entity_id>
```

This returns the entity's **current** group memberships (not necessarily what they were
at denial time, same caveat as step 2). Check whether any of them is an **external
group**: a root-namespace external group that's a member of an internal group inside a
tenant namespace, carrying a tenant policy, is the shape behind
`external_namespace_policies`.

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
that kind turns up, capture the raw `error` string: that's the one piece this guide
doesn't currently cover.

## What this cannot tell you

Whether the denial was a misconfiguration or someone probing. It scopes which policies
were in play and who the identity was; it does not establish intent. And if the token
has since been revoked and its entity deleted, step 3 has nothing left to look up.
Capture the entity_id while the trail is fresh.

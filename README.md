# vault-audit-dashboards

Splunk and Grafana dashboards for HashiCorp Vault, built by folding the **audit device**
stream. No tree walk, no plugin, no product feature required.

Vault can tell you a secret exists. It cannot readily tell you whether anything still
*uses* it, who used it, or what your audit stream is costing you. Those answers are already
in the audit log.

> **How many secrets has nothing read in the last eighteen months?**
> **Which workload read this credential, and what else does it touch?**
> **What is actually generating our audit ingest bill?**

## Pick your tool

| | |
|---|---|
| **[Splunk](splunk/README.md)** | Three dashboards plus a drop-in app. Self-contained: the fold happens in SPL, inside Splunk |
| **[Grafana](grafana/README.md)** | Dashboard JSON plus an aggregator. Grafana cannot do this fold itself, so the aggregator is required, not optional |

The numbers agree. Use whichever you already own.

## Walkthroughs

Step by step, with what each result means and where it can mislead you.

| | |
|---|---|
| [Who touched this secret?](splunk/scenarios/01-who-touched-this-secret.md) | Created, last written, last read, by whom, and the retention limit that makes "created by" harder than it looks |
| [Trace a transaction](splunk/scenarios/02-trace-a-transaction.md) | From a secret out to its consumers, or from a workload in to everything it touched |
| [Find stale secrets](splunk/scenarios/03-find-stale-secrets.md) | The cleanup list, and the one input without which the headline number is silently wrong |
| [Where is my audit volume coming from?](splunk/scenarios/04-where-is-my-audit-volume.md) | Turning "the logs are too big" into an evidence-based filtering argument |
| [Credential lease visibility](splunk/scenarios/05-credential-lease-visibility.md) | Azure/AWS/Database: live-polled, not audit-folded, because the audit log cannot record expiry |

## What you need

A Vault **audit device** stream. That is the only input. Everything else is derived.

One exception, and it matters: the hygiene dashboards also need a **baseline path
inventory**, a one-time list of every secret path. A secret nobody has ever read emits no
audit event, so it cannot appear in any search. It exists only in that list. Skip it and
the most important number is silently missing, with no error.

```
splunk/
  splunk-app/     Drop-in app: dashboards, sourcetype, indexes, auditor role
  dashboards/     The dashboard XML on its own
  searches/       The SPL on its own, heavily commented
  scenarios/      The walkthroughs above
grafana/
  dashboards/     Dashboard JSON
  scripts/        The KV hygiene aggregator, plus the credential lease poller
                  (Splunk keeps its own copy at splunk-app/.../bin/, source of truth here)
docs/             How it works, and how to test it
```

## The two traps

**Secret path can never be a label.** A large estate has hundreds of thousands of KV v2
secrets. As a Prometheus or Loki label that is hundreds of thousands of active series, and
it kills the index. The fold happens in a stateful process; only aggregates cross the wire.
Splunk has no such limit, which is why the Splunk route needs no external process and the
Grafana route does.

**"Never read" is invisible without the baseline inventory.** See above. It is the number
most worth having and the one that disappears most quietly.

Both are covered in [`docs/how-it-works.md`](docs/how-it-works.md), along with the audit
schema, the fold rules, and the scale numbers.

## Safety

The Vault audit device HMAC-SHA256s every secret value before writing it. **No panel here
can render a secret, because no secret value exists in the input.** That is what makes
these searches safe to point at a regulated namespace.

## Status

A community-built asset, not a HashiCorp product feature. It exists because the audit log
already contains these answers and folding them is not hard.

Every panel and search has been executed against a live Splunk instance, not just reviewed.
The hygiene numbers were reconciled against known ground truth, and the field handling was
validated against real Vault audit output rather than assumed. That testing found four bugs
a code review had already missed, and all four rendered a dashboard that looked perfectly
healthy while being wrong. [`docs/TESTING.md`](docs/TESTING.md) has the four checks that
catch them.

One file, `splunk/searches/tls-noise.spl`, has never been run against data, because it
reads Vault server logs rather than the audit device. It says so at the top.

Licensed under MPL-2.0.

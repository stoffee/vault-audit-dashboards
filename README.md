# vault-audit-dashboards

Splunk and Grafana dashboards that answer secret-hygiene questions about HashiCorp Vault by
folding the **audit device** stream. No tree walk, no plugin, no product feature required.

> **How many secrets has nothing read in the last eighteen months?**

Vault can tell you a secret exists. It cannot readily tell you whether anything still *uses*
it. That answer is in the audit log.

![Vault secret hygiene dashboard](docs/images/01-dashboard-overview.jpg)

## What you get

| | |
|---|---|
| 🔎 **Secrets nobody has ever read** | The dormant-cleanup list, including secrets that emit no audit event at all |
| 🔁 **Rotated but never read** | A rotation job rewriting a credential no workload has ever consumed |
| 📊 **Last-read age distribution** | 30 / 90 / 180 / 365 / 540-day buckets, by namespace |
| 👤 **Who read this secret** | Kubernetes service account, CI pipeline, source IP, and timestamp |
| 🧹 **Dead auth mounts** | Mounts that survived a decommission and are still taking logins |

```
splunk/    SPL searches + a Simple XML dashboard
grafana/   Dashboard JSON, fed by scripts/vault-secret-aggregator.py
```

Pick whichever tool you already own. The numbers agree.

![Cleanup candidates](docs/images/02-cleanup-candidates.jpg)

Every row is a credential that a rotation job is still faithfully rewriting and that
**nothing has ever read**. One of them was rotated the same day.

## Quick start

```bash
cd splunk
python3 generate-sample.py --paths 500 --events 4000 --logins 1000 --out samples/audit.jsonl
python3 generate-sample.py --expected      # ground truth it should reproduce

cd ..
python3 scripts/vault-secret-aggregator.py \
    --audit      splunk/samples/audit.jsonl \
    --inventory  splunk/samples/vault_secret_inventory.csv \
    --state-file .state/vault-secret-state.json \
    --print
```

`--print` needs nothing but Python 3. Add `--pushgateway` and `--loki` to publish into
Grafana; see [`grafana/README.md`](grafana/README.md). For Splunk, see
[`splunk/README.md`](splunk/README.md).

Against a real cluster, point `--audit` at your audit device output instead.

## The two traps

**Secret path can never be a label.** A large estate has hundreds of thousands of KV v2
secrets. As a Prometheus or Loki label that is hundreds of thousands of active series, and
it kills the index. The fold happens in a stateful process; only aggregates cross the wire.

**"Never read" is invisible without a baseline inventory.** A secret nobody has read emits
*no audit event*, so it cannot appear in any search. It exists only in a one-time path list.
Skip that join and the most important number is silently missing, with no error.

Both are covered in [`docs/how-it-works.md`](docs/how-it-works.md), along with the audit
schema, the fold rules, and the scale numbers.

## Safety

The Vault audit device HMAC-SHA256s every secret value before writing it. **No panel here
can render a secret, because no secret value exists in the input.** That is what makes these
searches safe against a regulated namespace.

Sample data is synthetic; the *schema* is real, copied from a live Vault audit entry. Both
dashboards carry a SAMPLE DATA banner as their first panel. Don't crop it out.

## Status

A community-built asset, not a HashiCorp product feature. It exists because the audit log
already contains this answer and folding it is not hard.

Licensed under MPL-2.0.

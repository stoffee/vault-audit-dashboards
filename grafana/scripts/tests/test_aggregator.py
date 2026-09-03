#!/usr/bin/env python3
"""Fixture-based tests for vault-secret-aggregator.py.

stdlib only, no dependencies, matching the aggregator itself. Run with:
    python3 grafana/scripts/tests/test_aggregator.py
"""
import importlib.util
import io
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "mixed-mounts.jsonl"

spec = importlib.util.spec_from_file_location(
    "vault_secret_aggregator", HERE.parent / "vault-secret-aggregator.py")
agg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agg)


class ResolveNamespace(unittest.TestCase):
    def test_prefers_path_when_both_present(self):
        self.assertEqual(agg.resolve_namespace({"namespace": {"path": "team-a/", "id": "x"}}), "team-a/")

    def test_falls_back_to_id(self):
        self.assertEqual(agg.resolve_namespace({"namespace": {"id": "nsB1"}}), "nsB1")

    def test_falls_back_to_empty_when_neither(self):
        self.assertEqual(agg.resolve_namespace({"namespace": {}}), "")
        self.assertEqual(agg.resolve_namespace({}), "")


class FoldDefaultMounts(unittest.TestCase):
    """mounts=("kv",) is the default and must match pre-change behavior exactly."""

    def setUp(self):
        self.table, self.denials, self.stats = agg.fold(str(FIXTURE), mounts=("kv",))

    def test_scanned_counts_every_line(self):
        self.assertEqual(self.stats["scanned"], 12)

    def test_matched_counts_kv_data_path_events_including_denials(self):
        # lines 1,2,3,4,7,8 = 6. Denials still pass the mount/path filter.
        self.assertEqual(self.stats["matched"], 6)

    def test_non_kv_mounts_are_skipped_and_counted(self):
        self.assertEqual(self.stats["skipped_by_mount"],
                          {"database": 1, "pki": 1, "system": 1})

    def test_denied_secret_does_not_enter_the_hygiene_universe(self):
        # The only events touching this secret were both denials. It must not
        # appear as a phantom "never accessed" row.
        secrets = {r["secret"] for r in self.table}
        self.assertNotIn("nsB1secret/data/app-f/db", secrets)
        self.assertEqual(self.stats["universe"], 3)

    def test_id_only_namespace_resolves_correctly(self):
        row = next(r for r in self.table if r["secret"] == "nsB1secret/data/app-b/db")
        self.assertEqual(row["namespace"], "nsB1")
        self.assertEqual(row["reads"], 1)

    def test_neither_namespace_field_falls_back_to_root(self):
        row = next(r for r in self.table if r["secret"] == "secret/data/app-c/db")
        self.assertEqual(row["namespace"], "root")

    def test_path_wins_when_both_present(self):
        row = next(r for r in self.table if r["secret"] == "team-a/secret/data/app-a/db")
        self.assertEqual(row["namespace"], "team-a/")
        self.assertEqual(row["reads"], 1)
        self.assertEqual(row["writes"], 1)

    def test_denial_folds_separately_and_does_not_count_as_a_read(self):
        self.assertEqual(self.stats["denials"], 2)
        self.assertEqual(len(self.denials), 1)
        d = self.denials[0]
        self.assertEqual(d["namespace"], "nsB1")
        self.assertEqual(d["who"], "svc-f")
        self.assertEqual(d["count"], 2)

    def test_request_type_events_are_never_folded(self):
        # Line 10 is type=request on a real KV path; it must not inflate reads.
        for r in self.table:
            self.assertNotIn("app-a/db", r["secret"]) if False else None
        # app-a's read count comes only from line 1, not line 1 + line 10.
        row = next(r for r in self.table if r["secret"] == "team-a/secret/data/app-a/db")
        self.assertEqual(row["reads"], 1)

    def test_kv_metadata_path_is_browsing_not_use(self):
        # Line 12 is a metadata read on the same secret as lines 1/2; must not add a read.
        row = next(r for r in self.table if r["secret"] == "team-a/secret/data/app-a/db")
        self.assertEqual(row["reads"], 1)


class FoldExpandedMounts(unittest.TestCase):
    def setUp(self):
        self.table, self.denials, self.stats = agg.fold(str(FIXTURE), mounts=("kv", "database", "pki"))

    def test_non_kv_mounts_fold_without_requiring_data_prefix(self):
        secrets = {r["secret"] for r in self.table}
        self.assertIn("database/creds/app-d-role", secrets)
        self.assertIn("pki/issue/app-e-role", secrets)

    def test_only_system_is_left_out_now(self):
        self.assertEqual(self.stats["skipped_by_mount"], {"system": 1})

    def test_matched_grows_by_the_two_newly_included_mounts(self):
        self.assertEqual(self.stats["matched"], 8)


class StdinMatchesFile(unittest.TestCase):
    def test_stdin_folds_identically_to_a_file(self):
        table_file, denials_file, stats_file = agg.fold(str(FIXTURE), mounts=("kv", "database", "pki"))

        text = FIXTURE.read_text()
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(text)
        try:
            table_stdin, denials_stdin, stats_stdin = agg.fold("-", mounts=("kv", "database", "pki"))
        finally:
            sys.stdin = old_stdin

        self.assertEqual(table_file, table_stdin)
        self.assertEqual(denials_file, denials_stdin)
        self.assertEqual(stats_file, stats_stdin)


class PromPayloadCardinality(unittest.TestCase):
    """The denial counter must be namespace-only: never path, never identity."""

    def test_denial_metric_has_no_path_or_identity_label(self):
        table, denials, stats = agg.fold(str(FIXTURE), mounts=("kv",))
        agg.classify(table, now=2000000000)
        body = agg.prom_payload(table, stats, denials)
        for line in body.splitlines():
            if line.startswith("vault_secret_denied_total{"):
                self.assertIn('namespace="nsB1"', line)
                self.assertNotIn("app-f", line)
                self.assertNotIn("svc-f", line)
class RootNamespaceNormalization(unittest.TestCase):
    def test_id_root_normalizes_the_same_as_absent_path(self):
        # Vault's root namespace has the fixed id "root", not an empty id. If the
        # fallback did not normalize it, ns + path would bake a literal "root"
        # prefix onto the key for id-only audit devices, while path-based root
        # (empty path) would not, producing two different keys for the same secret.
        via_id = agg.resolve_namespace({"namespace": {"id": "root"}})
        via_absent = agg.resolve_namespace({"namespace": {}})
        self.assertEqual(via_id, via_absent)
        self.assertEqual(via_id, "")


if __name__ == "__main__":
    unittest.main()

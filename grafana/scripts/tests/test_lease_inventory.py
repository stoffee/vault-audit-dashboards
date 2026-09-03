#!/usr/bin/env python3
"""Unit tests for vault-lease-inventory.py's pure logic (bucketing, time parsing,
classification). The HTTP-calling parts (poll()) were verified live against a real
Vault, a real Postgres backend, and real issued leases this session; that is not
something a fixture can substitute for, so it is not re-tested here. This file covers
what CAN be tested deterministically and offline.

Run with: python3 grafana/scripts/tests/test_lease_inventory.py
"""
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "vault_lease_inventory", HERE.parent / "vault-lease-inventory.py")
lease = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lease)


class ParseIso(unittest.TestCase):
    def test_parses_vault_rfc3339_with_offset(self):
        # Exact shape verified from a real Vault: sub-second precision, numeric offset.
        ts = lease.parse_iso("2026-09-03T13:52:26.946649-07:00")
        self.assertIsNotNone(ts)

    def test_none_in_none_out(self):
        self.assertIsNone(lease.parse_iso(None))
        self.assertIsNone(lease.parse_iso(""))


class BucketForSeconds(unittest.TestCase):
    def test_none_is_unknown(self):
        self.assertEqual(lease.bucket_for_seconds(None), "unknown")

    def test_expired_is_its_own_bucket(self):
        self.assertEqual(lease.bucket_for_seconds(0), "0 expired")
        self.assertEqual(lease.bucket_for_seconds(-5), "0 expired")

    def test_within_one_hour(self):
        self.assertEqual(lease.bucket_for_seconds(1800), "1 <=1h")

    def test_within_one_day_not_one_hour(self):
        self.assertEqual(lease.bucket_for_seconds(3600 * 12), "2 <=1d")

    def test_within_one_week(self):
        self.assertEqual(lease.bucket_for_seconds(3600 * 24 * 3), "3 <=7d")

    def test_within_one_month(self):
        self.assertEqual(lease.bucket_for_seconds(3600 * 24 * 20), "4 <=30d")

    def test_beyond_one_month(self):
        self.assertEqual(lease.bucket_for_seconds(3600 * 24 * 90), "5 >30d")

    def test_buckets_sort_correctly_as_strings(self):
        # The number prefix exists so string-sorting (what Splunk and Grafana both do
        # on a bucket field) produces chronological order, not alphabetical nonsense.
        buckets = [lease.bucket_for_seconds(s) for s in
                   (1800, 3600 * 12, 3600 * 24 * 3, 3600 * 24 * 20, 3600 * 24 * 90)]
        self.assertEqual(buckets, sorted(buckets))


class Classify(unittest.TestCase):
    def test_computes_days_to_expiry_and_seconds_remaining(self):
        now = 1_000_000_000
        rows = [{"issue_time": now - 3600, "expire_time": now + 3600 * 5}]
        out = lease.classify(rows, now)
        self.assertEqual(out[0]["seconds_to_expiry"], 3600 * 5)
        self.assertAlmostEqual(out[0]["days_to_expiry"], 3600 * 5 / 86400, places=2)
        self.assertEqual(out[0]["age_seconds"], 3600)

    def test_five_hours_lands_in_the_one_day_bucket_not_one_hour(self):
        now = 1_000_000_000
        rows = [{"issue_time": now, "expire_time": now + 3600 * 5}]
        out = lease.classify(rows, now)
        self.assertEqual(out[0]["bucket"], "2 <=1d")

    def test_missing_expire_time_is_unknown_not_a_crash(self):
        now = 1_000_000_000
        rows = [{"issue_time": now, "expire_time": None}]
        out = lease.classify(rows, now)
        self.assertIsNone(out[0]["seconds_to_expiry"])
        self.assertEqual(out[0]["bucket"], "unknown")


class EngineTypesTable(unittest.TestCase):
    def test_only_database_is_marked_verified(self):
        # This must stay true until aws/azure are actually tested against a real
        # backend. If this test starts failing because someone flipped it to True
        # without doing that, it is doing its job.
        self.assertTrue(lease.ENGINE_TYPES["database"]["verified"])
        self.assertFalse(lease.ENGINE_TYPES["aws"]["verified"])
        self.assertFalse(lease.ENGINE_TYPES["azure"]["verified"])


if __name__ == "__main__":
    unittest.main()

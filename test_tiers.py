"""Tests for plans and monthly check limits (tiers.py).

Run:  python -m unittest test_tiers -v
"""

import os
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

import tiers

NOV = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
DEC = datetime(2026, 12, 1, 0, 0, 1, tzinfo=timezone.utc)


class TestPlans(unittest.TestCase):

    def test_prices_and_features(self):
        self.assertEqual(tiers.PLANS["free"].price, "R0/month")
        self.assertEqual(tiers.PLANS["plus"].price, "R70/month")
        self.assertEqual(tiers.PLANS["pro"].price, "R90/month")
        self.assertFalse(tiers.PLANS["free"].documents)
        self.assertFalse(tiers.PLANS["plus"].documents)
        self.assertFalse(tiers.PLANS["plus"].reports)
        self.assertTrue(tiers.PLANS["pro"].documents)
        self.assertTrue(tiers.PLANS["pro"].reports)

    def test_plan_from_clerk_claims(self):
        self.assertEqual(tiers.plan_from_claims({"plan": "pro"}), "pro")
        self.assertEqual(tiers.plan_from_claims({"plan": " PLUS "}), "plus")
        self.assertEqual(tiers.plan_from_claims({"public_metadata": {"plan": "pro"}}), "pro")

    def test_unknown_or_missing_plan_is_free(self):
        for claims in (None, {}, {"plan": ""}, {"plan": "platinum"}, {"public_metadata": "pro"},
                       {"plan": None, "public_metadata": None}):
            with self.subTest(claims=claims):
                self.assertEqual(tiers.plan_from_claims(claims), "free")

    def test_default_limits(self):
        self.assertIsNone(tiers.monthly_limit("free", {}))  # Free: unchanged, no monthly limit
        self.assertEqual(tiers.monthly_limit("plus", {}), 100)
        self.assertEqual(tiers.monthly_limit("pro", {}), 300)

    def test_limits_are_configurable(self):
        env = {"SCAMSHIELD_PLUS_MONTHLY_CHECKS": "5", "SCAMSHIELD_PRO_MONTHLY_CHECKS": "nonsense"}
        self.assertEqual(tiers.monthly_limit("plus", env), 5)
        self.assertEqual(tiers.monthly_limit("pro", env), 300)  # bad value -> default

    def test_local_test_plan(self):
        self.assertEqual(tiers.local_test_plan({}), "free")
        self.assertEqual(tiers.local_test_plan({"SCAMSHIELD_LOCAL_TEST_PLAN": "pro"}), "pro")

    def test_reset_dates(self):
        self.assertEqual(tiers.month_key(NOV), "2026-11")
        self.assertEqual(tiers.next_reset(NOV), "2026-12-01")
        self.assertEqual(tiers.next_reset(datetime(2026, 12, 31, tzinfo=timezone.utc)), "2027-01-01")


class TestUsageStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = tiers.UsageStore(os.path.join(self.tmp.name, "usage.sqlite3"))

    def tearDown(self):
        self.store._db.close()
        self.tmp.cleanup()

    def test_limit_is_enforced(self):
        for expected in (1, 2, 3):
            self.assertEqual(self.store.reserve("user_a", 3, NOV), expected)
        with self.assertRaises(tiers.CheckLimitReached) as caught:
            self.store.reserve("user_a", 3, NOV)
        self.assertIn("2026-12-01", str(caught.exception))
        self.assertEqual(self.store.used("user_a", NOV), 3)

    def test_usage_resets_each_month(self):
        self.store.reserve("user_a", 1, NOV)
        with self.assertRaises(tiers.CheckLimitReached):
            self.store.reserve("user_a", 1, NOV)
        self.assertEqual(self.store.used("user_a", DEC), 0)
        self.assertEqual(self.store.reserve("user_a", 1, DEC), 1)

    def test_accounts_are_counted_separately(self):
        self.store.reserve("user_a", 1, NOV)
        self.assertEqual(self.store.reserve("user_b", 1, NOV), 1)

    def test_failed_check_is_given_back(self):
        self.store.reserve("user_a", 1, NOV)
        self.store.release("user_a", NOV)
        self.assertEqual(self.store.used("user_a", NOV), 0)
        self.store.release("user_a", NOV)  # never below zero
        self.assertEqual(self.store.used("user_a", NOV), 0)

    def test_no_limit_records_nothing(self):
        self.assertIsNone(self.store.reserve("user_a", None, NOV))
        self.assertEqual(self.store.used("user_a", NOV), 0)

    def test_simultaneous_checks_cannot_exceed_limit(self):
        allowed = []

        def attempt():
            try:
                self.store.reserve("user_a", 10, NOV)
                allowed.append(1)
            except tiers.CheckLimitReached:
                pass

        threads = [threading.Thread(target=attempt) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(allowed), 10)
        self.assertEqual(self.store.used("user_a", NOV), 10)

    def test_counts_survive_reopening(self):
        self.store.reserve("user_a", 5, NOV)
        reopened = tiers.UsageStore(self.store.path)
        self.assertEqual(reopened.used("user_a", NOV), 1)
        reopened._db.close()

    def test_account_summary(self):
        self.store.reserve("user_a", 100, NOV)
        with mock.patch.dict(os.environ, {"SCAMSHIELD_PLUS_MONTHLY_CHECKS": "100"}):
            summary = tiers.account_summary("user_a", "plus", self.store, NOV)
        self.assertEqual((summary["plan_name"], summary["checks_used"], summary["checks_left"]),
                         ("Plus", 1, 99))
        self.assertFalse(summary["documents"])
        self.assertTrue(summary["upgrade_message"])
        free = tiers.account_summary("user_a", "free", self.store, NOV)
        self.assertIsNone(free["monthly_limit"])
        self.assertIsNone(free["checks_used"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

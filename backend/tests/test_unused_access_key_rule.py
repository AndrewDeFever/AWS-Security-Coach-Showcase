import datetime
import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "src" / "runner" / "unused_access_key_rule.py"
SPEC = importlib.util.spec_from_file_location("unused_access_key_rule", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NOW = datetime.datetime(2026, 8, 22, tzinfo=datetime.UTC)


def row(*, user="alice", active="TRUE", last_used="N/A", created="2026-08-01T00:00:00+00:00"):
    return {
        "user": user,
        "access_key_1_active": active,
        "access_key_1_last_used_date": last_used,
        "access_key_1_last_rotated": created,
        "access_key_2_active": "FALSE",
        "access_key_2_last_used_date": "N/A",
        "access_key_2_last_rotated": "N/A",
    }


class UnusedAccessKeyRuleTests(unittest.TestCase):
    def test_baseline_is_90_days(self):
        self.assertEqual(MODULE.UNUSED_ACCESS_KEY_DAYS, 90)

    def test_never_used_key_younger_than_90_days_passes(self):
        result = MODULE.evaluate([row(created="2026-07-01T00:00:00+00:00")], now=NOW)
        self.assertEqual(result["status"], "PASS")

    def test_never_used_key_exactly_90_days_old_fails(self):
        created = NOW - datetime.timedelta(days=90)
        result = MODULE.evaluate([row(created=created.isoformat())], now=NOW)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("never used; 90 days old", result["details"])

    def test_key_last_used_89_days_ago_passes(self):
        used = NOW - datetime.timedelta(days=89)
        result = MODULE.evaluate([row(last_used=used.isoformat(), created="2025-01-01T00:00:00+00:00")], now=NOW)
        self.assertEqual(result["status"], "PASS")

    def test_key_last_used_exactly_90_days_ago_fails(self):
        used = NOW - datetime.timedelta(days=90)
        result = MODULE.evaluate([row(last_used=used.isoformat(), created="2025-01-01T00:00:00+00:00")], now=NOW)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("last used 90 days ago", result["details"])

    def test_active_never_used_key_without_creation_date_is_error(self):
        result = MODULE.evaluate([row(created="N/A")], now=NOW)
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("no usable creation date", result["details"])

    def test_root_row_is_excluded(self):
        result = MODULE.evaluate([row(user="<root_account>", created="2020-01-01T00:00:00+00:00")], now=NOW)
        self.assertEqual(result["status"], "PASS")


if __name__ == "__main__":
    unittest.main()

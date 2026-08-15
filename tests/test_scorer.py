"""Self-test for the detection scorer.

Runs the join as a pure function over committed fixtures, so the scoring logic
is verifiable without a live Docker stack. Run from the repo root:

    python -m unittest tests.test_scorer      # or: python tests/test_scorer.py
"""

import json
import os
import sys
import unittest

# Make the repo root importable when run as a bare script.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from netguard import scorer  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _load(name):
    with open(os.path.join(FIX, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


class TimestampTests(unittest.TestCase):
    def test_offset_without_colon(self):
        # Suricata's native format; rejected by fromisoformat before 3.11.
        self.assertAlmostEqual(
            scorer.parse_eve_timestamp("2023-11-14T22:15:03.000000+0000"),
            1700000103.0,
        )

    def test_offset_with_colon_and_z_and_bare(self):
        self.assertAlmostEqual(scorer.parse_eve_timestamp("2023-11-14T22:15:03+00:00"), 1700000103.0)
        self.assertAlmostEqual(scorer.parse_eve_timestamp("2023-11-14T22:15:03Z"), 1700000103.0)
        self.assertAlmostEqual(scorer.parse_eve_timestamp("2023-11-14T22:15:03"), 1700000103.0)

    def test_nonzero_offset_normalizes_to_utc(self):
        # 23:15:03 +01:00 is the same instant as 22:15:03 UTC.
        self.assertAlmostEqual(
            scorer.parse_eve_timestamp("2023-11-14T23:15:03+0100"), 1700000103.0
        )

    def test_bad_timestamp_raises(self):
        with self.assertRaises(ValueError):
            scorer.parse_eve_timestamp("not-a-timestamp")


class ScoreFixtureTests(unittest.TestCase):
    def setUp(self):
        self.manifest = _load("manifest.json")
        self.events = scorer.load_events(os.path.join(FIX, "eve.json"))
        self.card = scorer.score(self.manifest, self.events)
        self.rows = {r["id"]: r for r in self.card["per_technique"]}

    def test_capture_is_live(self):
        self.assertTrue(self.card["valid"])
        self.assertTrue(self.card["capture"]["live"])

    def test_recall_and_aggregate(self):
        agg = self.card["aggregate"]
        self.assertEqual(agg["attacks_total"], 3)
        self.assertEqual(agg["attacks_detected"], 2)
        self.assertAlmostEqual(agg["recall"], round(2 / 3, 4))
        self.assertEqual(agg["fp_count"], 1)
        self.assertEqual(agg["tp_alerts"], 2)
        self.assertEqual(agg["fp_alerts"], 1)
        self.assertAlmostEqual(agg["precision"], round(2 / 3, 4))
        self.assertAlmostEqual(agg["mttd_seconds"], 4.0)

    def test_a01_detected_excludes_demo_and_generator_alerts(self):
        a01 = self.rows["A01"]
        self.assertTrue(a01["detected"])
        # Only the real ET alert counts: the demo-sid alert (1000004) and the
        # generator-sourced alert (10.10.0.30) in the same window are excluded.
        self.assertEqual(a01["alert_count"], 1)
        self.assertAlmostEqual(a01["first_alert_delay_s"], 3.0)

    def test_a04_detected(self):
        self.assertTrue(self.rows["A04"]["detected"])
        self.assertAlmostEqual(self.rows["A04"]["first_alert_delay_s"], 5.0)

    def test_a08_missed(self):
        self.assertFalse(self.rows["A08"]["detected"])
        self.assertEqual(self.rows["A08"]["alert_count"], 0)

    def test_n01_false_positive(self):
        self.assertTrue(self.rows["N01"]["false_positive"])
        self.assertEqual(self.rows["N01"]["alert_count"], 1)


class DeadCaptureTests(unittest.TestCase):
    def test_no_events_is_invalid_run_not_zero_score(self):
        manifest = _load("manifest.json")
        card = scorer.score(manifest, [])
        self.assertFalse(card["valid"])
        self.assertEqual(card["result"], "INVALID_RUN")
        self.assertIsNone(card["aggregate"])

    def test_only_stats_events_is_invalid(self):
        manifest = _load("manifest.json")
        stats_only = [{"event_type": "stats", "epoch": 1700000105.0, "src_ip": None, "dest_ip": None}]
        card = scorer.score(manifest, stats_only)
        self.assertFalse(card["valid"])


class BaselineGateTests(unittest.TestCase):
    def test_not_yet_run_baseline_skips_gate(self):
        card = scorer.score(_load("manifest.json"), scorer.load_events(os.path.join(FIX, "eve.json")))
        cmp = scorer.compare_baseline(card, {"status": "not_yet_run", "metrics": None})
        self.assertEqual(cmp["gate"], "skipped")

    def test_recall_regression_fails_gate(self):
        card = scorer.score(_load("manifest.json"), scorer.load_events(os.path.join(FIX, "eve.json")))
        baseline = {"status": "established", "metrics": {"recall": 1.0, "fp_count": 0}}
        cmp = scorer.compare_baseline(card, baseline)
        self.assertEqual(cmp["gate"], "fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)

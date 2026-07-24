"""Unit tests for the Alerter — dedup, baseline silence, quiet hours, and the file
dedup backend's durability. Pure stdlib (unittest); SMTP is stubbed by replacing
``_send`` with a recorder, so nothing goes over the network.

    python -m unittest tests.test_alerts       # from the repo root
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dojo_dash.alerts import Alerter  # noqa: E402

LA = ZoneInfo("America/Los_Angeles")


def la_epoch(hour):
    """A concrete epoch at `hour` local (America/Los_Angeles) on a fixed summer date."""
    return datetime(2026, 7, 23, hour, 0, tzinfo=LA).timestamp()


def mk(fid, sev="High"):
    """A minimal open, alert-worthy finding row (see render._disposition)."""
    return {"finding_id": fid, "severity": sev, "title": f"finding {fid}",
            "product": "web-app", "environment": "Production",
            "active": True, "duplicate": False, "out_of_scope": False}


def make_alerter(dedup=None, quiet=None):
    cfg = {"enabled": True, "severities": ["Critical", "High"],
           "recipients": ["a@example.com"], "min_interval_seconds": 0}
    if quiet is not None:
        cfg["quiet_hours"] = quiet
    if dedup is not None:
        cfg["dedup"] = dedup
    a = Alerter(cfg, env={"ALERT_SMTP_URL": "smtp://localhost"})
    sent = []
    a._send = lambda batch: sent.append([f["finding_id"] for f in batch])  # stub SMTP
    return a, sent


class BaselineDedupTests(unittest.TestCase):
    def test_baseline_is_silent_then_alerts_new_once(self):
        a, sent = make_alerter()  # memory backend, no quiet hours
        a.process([mk(1), mk(2)])          # first poll: baseline the backlog
        self.assertEqual(sent, [])
        self.assertTrue(a.primed)
        self.assertEqual(a.seen, {1, 2})

        a.process([mk(1), mk(2), mk(3)])   # a new finding appears
        self.assertEqual(sent, [[3]])
        a.process([mk(1), mk(2), mk(3)])   # same set again -> no re-alert
        self.assertEqual(sent, [[3]])

    def test_send_failure_keeps_pending_and_retries(self):
        a, sent = make_alerter()
        a.process([mk(1)])                 # baseline
        boom = {"fail": True}

        def flaky(batch):
            if boom["fail"]:
                raise RuntimeError("smtp down")
            sent.append([f["finding_id"] for f in batch])
        a._send = flaky

        a.process([mk(1), mk(2)])          # send raises -> nothing recorded, 2 stays pending
        self.assertEqual(sent, [])
        self.assertNotIn(2, a.seen)
        self.assertIn(2, a.pending)

        boom["fail"] = False
        a.process([mk(1), mk(2)])          # retry succeeds
        self.assertEqual(sent, [[2]])
        self.assertIn(2, a.seen)
        self.assertEqual(a.pending, {})


class QuietHoursTests(unittest.TestCase):
    QUIET = {"tz": "America/Los_Angeles", "start": 8, "end": 20, "gate_all": True}

    def test_hold_off_hours_then_flush_when_window_opens(self):
        a, sent = make_alerter(quiet=self.QUIET)
        a.process([mk(1)], now=la_epoch(9))            # baseline (in-window, but silent anyway)
        a.process([mk(1), mk(2)], now=la_epoch(2))     # 2am: held, not sent
        self.assertEqual(sent, [])
        self.assertIn(2, a.pending)
        a.process([mk(1), mk(2)], now=la_epoch(9))     # 9am: flushes
        self.assertEqual(sent, [[2]])
        self.assertEqual(a.pending, {})

    def test_gate_all_holds_critical_overnight(self):
        a, sent = make_alerter(quiet=self.QUIET)
        a.process([mk(1)], now=la_epoch(9))
        a.process([mk(1), mk(2, "Critical")], now=la_epoch(2))  # gate_all: Critical waits too
        self.assertEqual(sent, [])
        self.assertIn(2, a.pending)

    def test_critical_bypasses_when_gate_all_false(self):
        quiet = dict(self.QUIET, gate_all=False)
        a, sent = make_alerter(quiet=quiet)
        a.process([mk(1)], now=la_epoch(9))
        # 2am: Critical pages immediately; High is held.
        a.process([mk(1), mk(2, "Critical"), mk(3, "High")], now=la_epoch(2))
        self.assertEqual(sent, [[2]])
        self.assertIn(3, a.pending)
        self.assertNotIn(2, a.pending)


class FileBackendDurabilityTests(unittest.TestCase):
    def test_file_store_survives_restart_without_rebaselining(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dedup.json")
            dedup = {"backend": "file", "file": {"path": path}}

            a, sent_a = make_alerter(dedup=dedup)
            a.process([mk(1), mk(2)])          # baseline -> persisted
            a.process([mk(1), mk(2), mk(3)])   # alert 3 -> persisted
            self.assertEqual(sent_a, [[3]])

            # Simulate a container restart: a fresh Alerter reading the same file.
            b, sent_b = make_alerter(dedup=dedup)
            self.assertTrue(b.primed)          # loaded state, no re-baseline
            self.assertEqual(b.seen, {1, 2, 3})
            b.process([mk(1), mk(2), mk(3), mk(4)])   # only the genuinely-new 4 alerts
            self.assertEqual(sent_b, [[4]])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the control-registry sections (the compliance evidence view).

The property that matters most is DETERMINISM: these sections must render from the
checked-in registry alone, with no DefectDojo data reaching them. A compliance
assessor is handed a link to a specific claim about the codebase, and a number that
moves between submission and review is worse than no number. So the tests below pass
deliberately hostile finding data (a live Critical) and assert it changes nothing.

Pure stdlib (unittest), matching tests/test_alerts.py — CI installs only the package
(`pip install .[mongodb]`) and runs `python -m unittest discover -s tests`, so a test
dependency here would not be available.

    python -m unittest tests.test_control_registry     # from the repo root
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dojo_dash import render as R  # noqa: E402

REGISTRY = {
    "framework": {"label": "ASVS 4.0.3 Level 1", "source": "config/asvs_map.yaml"},
    "statuses": [
        {"key": "met", "label": "Met", "tone": "good"},
        {"key": "not-met", "label": "NOT MET", "tone": "bad"},
        {"key": "todo", "label": "TODO", "tone": "warn"},
    ],
    "attributes": [
        {"key": "how", "label": "How verified"},
        {"key": "evidence", "label": "Evidence"},
        {"key": "owner", "label": "Owner"},
    ],
    "groups": [{"id": "V2", "name": "Authentication"}, {"id": "V3", "name": "Session"}],
    "controls": [
        {"id": "V2.1.1", "group": "V2", "text": "Passwords are 12+ chars.",
         "status": "met", "attrs": {"how": "code-review", "evidence": "policy.py:44",
                                    "owner": "app"}},
        {"id": "V2.2.1", "group": "V2", "text": "Anti-automation on login.",
         "status": "not-met", "attrs": {"owner": "app"}, "notes": "No throttle yet."},
        {"id": "V3.1.1", "group": "V3", "text": "No session tokens in the URL.",
         "status": "todo", "attrs": {"owner": "security"},
         "decision": {
             "question": "Ship <b>now</b> or wait?",
             "options": ["Ship now", "Wait for the audit"],
             "recommendation": "Ship now — it is a one-line change.",
         }},
    ],
}

CFG = {"control_registry": {"file": "controls.json"}}

HOSTILE = [
    {"severity": "Critical", "product": "app", "engagement": "CI", "title": "boom",
     "age_days": 900, "finding_id": 1, "active": True, "duplicate": False,
     "risk_accepted": False, "false_p": False, "out_of_scope": False,
     "mitigated": None, "environment": "Production"},
]


class RegistryTestCase(unittest.TestCase):
    """Writes the registry to a temp file and points DOJO_DASH_CONTROLS at it."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        path = os.path.join(self._dir.name, "controls.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(REGISTRY, fh)
        self._prev = os.environ.get("DOJO_DASH_CONTROLS")
        os.environ["DOJO_DASH_CONTROLS"] = path

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("DOJO_DASH_CONTROLS", None)
        else:
            os.environ["DOJO_DASH_CONTROLS"] = self._prev
        self._dir.cleanup()

    @staticmethod
    def render_both(sections):
        """Same report with no findings vs. a live Critical, minus the time stamp."""
        report = {"title": "Evidence", "sections": sections}
        cfg = dict(CFG, severities=["Critical"])

        def strip(s):
            return "\n".join(ln for ln in s.splitlines() if "Generated" not in ln)

        return (strip(R.render_report(report, [], cfg)),
                strip(R.render_report(report, HOSTILE, cfg)))


class SummaryTests(RegistryTestCase):
    def test_counts_every_status(self):
        html = R.render_control_registry_summary(CFG, "Where we stand")
        self.assertIn('>3</div><div class="kpi-l">Requirements', html)
        for label in ("Met", "NOT MET", "TODO"):
            self.assertIn(label, html)
        self.assertIn("Authentication", html)
        self.assertIn("Session", html)


class FullMapTests(RegistryTestCase):
    def test_lists_every_control_with_its_evidence(self):
        html = R.render_control_registry(CFG, "Full map")
        for cid in ("V2.1.1", "V2.2.1", "V3.1.1"):
            self.assertIn(cid, html)
        # Evidence and notes are merged into one cell, so both must survive.
        self.assertIn("policy.py:44", html)
        self.assertIn("No throttle yet.", html)

    def test_statuses_filter_narrows_to_the_gaps(self):
        html = R.render_control_registry(CFG, "Open", statuses=["not-met", "todo"])
        self.assertIn("V2.2.1", html)
        self.assertIn("V3.1.1", html)
        self.assertNotIn("V2.1.1", html)


class DecisionTests(RegistryTestCase):
    def test_open_decisions_render_inline_and_are_escaped(self):
        """The person who has to make the call reads this page, so the question,
        options and recommendation all render in place — and since the registry is a
        file a human edits, its text is escaped rather than trusted as HTML."""
        html = R.render_control_registry(CFG, "Open items", statuses=["todo"])
        self.assertIn("Decision needed:", html)
        self.assertIn("Wait for the audit", html)
        self.assertIn("Ship now — it is a one-line change.", html)
        self.assertNotIn("<b>now</b>", html)
        self.assertIn("&lt;b&gt;now&lt;/b&gt;", html)

    def test_controls_without_a_decision_render_no_decision_block(self):
        html = R.render_control_registry(CFG, "Met only", statuses=["met"])
        self.assertNotIn("Decision needed:", html)


class DeterminismTests(RegistryTestCase):
    def test_render_is_independent_of_finding_data(self):
        """The whole point: Dojo findings must not move a single number here."""
        empty, hostile = self.render_both([
            {"kind": "control-registry-summary", "title": "Where we stand"},
            {"kind": "control-registry", "title": "Full map"},
        ])
        self.assertEqual(empty, hostile)

    def test_the_determinism_check_can_actually_fail(self):
        """Guard on the guard above.

        A comparison that can never differ would pass whatever the registry sections
        did, so pin the harness against a section that IS finding-derived (`kpis`).
        If this stops failing, the test above has quietly stopped proving anything.
        """
        empty, hostile = self.render_both([{"kind": "kpis", "title": "At a glance"}])
        self.assertNotEqual(empty, hostile)


class DegradationTests(unittest.TestCase):
    def test_missing_registry_degrades_instead_of_raising(self):
        prev = os.environ.get("DOJO_DASH_CONTROLS")
        os.environ["DOJO_DASH_CONTROLS"] = "/nonexistent/controls.json"
        try:
            for html in (R.render_control_registry_summary(CFG, "T"),
                         R.render_control_registry(CFG, "T")):
                self.assertIn("No control registry configured", html)
        finally:
            if prev is None:
                os.environ.pop("DOJO_DASH_CONTROLS", None)
            else:
                os.environ["DOJO_DASH_CONTROLS"] = prev


class MarkdownTests(RegistryTestCase):
    def test_gap_summary_only_emits_the_requested_statuses(self):
        md = R.md_control_registry(CFG, "Open items", statuses=["not-met"])
        self.assertIn("V2.2.1", md)
        self.assertNotIn("V2.1.1", md)


if __name__ == "__main__":
    unittest.main()


# ------------------------------------------------------- CASA page navigation

def _multi_section_report():
    return {"title": "CASA", "sections": [
        {"kind": "control-registry-summary", "title": "Where we stand"},
        {"kind": "control-registry", "title": "Open items", "statuses": ["not-met", "todo"]},
        {"kind": "control-registry", "title": "Full map", "tabs": True},
    ]}


class NavigationTests(RegistryTestCase):
    def test_summary_cards_and_cells_link_into_the_map(self):
        html = R.render_control_registry_summary(CFG, "Where we stand")
        assert 'href="#cr-map"' in html, "KPI cards must deep-link into the map"
        assert 'data-cr-status="met"' in html
        assert 'class="cr-cell"' in html, "matrix counts must be clickable"
        assert 'data-cr-group="V2"' in html

    def test_tabs_only_where_asked(self):
        with_tabs = R.render_control_registry(CFG, "Full map", sec_tabs=True)
        without = R.render_control_registry(CFG, "Open items", sec_tabs=False)
        assert 'class="cr-tab"' in with_tabs, "tabs: true must render a tab strip"
        assert 'class="cr-tab"' not in without, (
            "a short section must not get a tab strip it does not need")

    def test_rows_and_groups_carry_filter_hooks(self):
        html = R.render_control_registry(CFG, "Full map", sec_tabs=True)
        assert 'class="cr-group" data-cr-group="V2"' in html
        assert 'data-cr-status="met"' in html

    def test_only_one_section_owns_the_cr_map_anchor(self):
        """Both control-registry sections defaulting to id="cr-map" produced
        duplicate ids, and the filter script bound to whichever came first —
        which was the wrong section."""
        import re
        page = R.render_report(_multi_section_report(), [],
                               {**CFG, "severities": ["Critical"]})
        ids = re.findall(r'<section id="([^"]+)"', page)
        assert len(ids) == len(set(ids)), f"duplicate section ids: {ids}"
        assert ids.count("cr-map") == 1, f"exactly one cr-map expected, got {ids}"

    def test_the_tabbed_section_is_the_one_that_owns_cr_map(self):
        """The summary links to #cr-map, so the anchor must land on the full map
        rather than on Open items."""
        page = R.render_report(_multi_section_report(), [],
                               {**CFG, "severities": ["Critical"]})
        i = page.index('<section id="cr-map"')
        assert 'class="cr-tab"' in page[i:], "cr-map must be the tabbed section"
        assert 'class="cr-tab"' not in page[:i], "no tabs before the map section"

    def test_filter_script_is_scoped_to_the_map(self):
        """An unscoped filter made a chapter tab hide rows in Open items too."""
        page = R.render_report(_multi_section_report(), [],
                               {**CFG, "severities": ["Critical"]})
        assert "root.querySelectorAll('.cr-group')" in page
        assert "document.querySelectorAll('.cr-group')" not in page

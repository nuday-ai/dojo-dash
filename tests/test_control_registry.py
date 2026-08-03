"""Tests for the control-registry sections (the CASA / ASVS evidence view).

The property under test that matters most is DETERMINISM: these sections must render
from the checked-in registry alone, with no DefectDojo data reaching them. A
compliance assessor is handed a link to a specific claim about the codebase, and a
number that moves between submission and review is worse than no number. So the
tests below pass deliberately hostile finding data (a live Critical) and assert it
changes nothing.
"""
import json

import pytest

from dojo_dash import render as R

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


@pytest.fixture
def registry(tmp_path, monkeypatch):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps(REGISTRY), encoding="utf-8")
    monkeypatch.setenv("DOJO_DASH_CONTROLS", str(path))
    return path


def test_summary_counts_every_status(registry):
    html = R.render_control_registry_summary(CFG, "Where we stand")
    # 3 requirements: 1 met, 1 not-met, 1 todo — and the total card.
    assert ">3</div><div class=\"kpi-l\">Requirements" in html
    for label in ("Met", "NOT MET", "TODO"):
        assert label in html
    # Per-group rows exist for both chapters.
    assert "Authentication" in html and "Session" in html


def test_full_map_lists_every_control_with_its_evidence(registry):
    html = R.render_control_registry(CFG, "Full map")
    for cid in ("V2.1.1", "V2.2.1", "V3.1.1"):
        assert cid in html
    # Evidence and notes are merged into one cell, so both must survive.
    assert "policy.py:44" in html
    assert "No throttle yet." in html


def test_statuses_filter_narrows_to_the_gaps(registry):
    html = R.render_control_registry(CFG, "Open items", statuses=["not-met", "todo"])
    assert "V2.2.1" in html and "V3.1.1" in html
    assert "V2.1.1" not in html, "a met requirement leaked into the gaps section"


HOSTILE = [
    {"severity": "Critical", "product": "app", "engagement": "CI", "title": "boom",
     "age_days": 900, "finding_id": 1, "active": True, "duplicate": False,
     "risk_accepted": False, "false_p": False, "out_of_scope": False,
     "mitigated": None, "environment": "Production"},
]


def _render_both(sections):
    """Same report with no findings vs. a live Critical, minus the time stamp."""
    report = {"title": "CASA", "sections": sections}
    cfg = {**CFG, "severities": ["Critical"]}
    def strip(s):
        return "\n".join(line for line in s.splitlines() if "Generated" not in line)
    return (strip(R.render_report(report, [], cfg)),
            strip(R.render_report(report, HOSTILE, cfg)))


def test_render_is_independent_of_finding_data(registry):
    """The whole point: Dojo findings must not move a single number here."""
    empty, hostile = _render_both([
        {"kind": "control-registry-summary", "title": "Where we stand"},
        {"kind": "control-registry", "title": "Full map"},
    ])
    assert empty == hostile


def test_the_determinism_check_can_actually_fail():
    """Guard on the guard above.

    A comparison that can never differ would pass whatever the registry sections
    did, so pin the harness against a section that IS finding-derived (`kpis`). If
    this stops failing, the test above has quietly stopped proving anything.
    """
    empty, hostile = _render_both([{"kind": "kpis", "title": "At a glance"}])
    assert empty != hostile


def test_open_decisions_render_inline_and_are_escaped(registry):
    """The person who has to make the call reads this page, so the question, the
    options and the recommendation all render in place — and, since the registry is
    a file a human edits, its text is escaped rather than trusted as HTML."""
    html = R.render_control_registry(CFG, "Open items", statuses=["todo"])
    assert "Decision needed:" in html
    assert "Wait for the audit" in html
    assert "Ship now — it is a one-line change." in html
    assert "<b>now</b>" not in html, "registry text was interpolated as raw HTML"
    assert "&lt;b&gt;now&lt;/b&gt;" in html


def test_controls_without_a_decision_render_no_decision_block(registry):
    html = R.render_control_registry(CFG, "Met only", statuses=["met"])
    assert "Decision needed:" not in html


def test_missing_registry_degrades_instead_of_raising(monkeypatch):
    monkeypatch.setenv("DOJO_DASH_CONTROLS", "/nonexistent/controls.json")
    for html in (R.render_control_registry_summary(CFG, "T"),
                 R.render_control_registry(CFG, "T")):
        assert "No control registry configured" in html


def test_markdown_gap_summary_only_emits_the_requested_statuses(registry):
    md = R.md_control_registry(CFG, "Open items", statuses=["not-met"])
    assert "V2.2.1" in md
    assert "V2.1.1" not in md

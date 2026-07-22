"""Optional risk-acceptance enrichment for the report.

DefectDojo already knows which findings are risk-accepted (the `risk_accepted` flag)
and when (the risk_acceptance object's decision_date). This module is a thin, OPTIONAL
layer on top: if you keep a `suppressions.yaml` register of accepted risks with a
justification / owner / re-review trigger, the report attaches that context to the
matching accepted findings (shown in a popover on the findings page).

It is entirely best-effort — with no `suppressions.yaml` present, the report still
renders; accepted findings just won't carry the extra justification text. Point at the
file with $DOJO_DASH_SUPPRESSIONS (defaults to ./config/suppressions.yaml).

Expected shape (only these keys are read):

    suppressions:
      - id: RA-1
        kind: accepted-risk          # only accepted-risk entries are used here
        justification: "Why this risk is accepted."
        owner: "Platform team"
        re_review_trigger: "Next base-image bump."
        match:
          rules:  ["CVE-2023-1234"]  # substring-matched against the finding text
          checks: ["CKV_AWS_20"]     # (rules + checks are treated the same)
          paths:  ["usr/lib/**"]     # fnmatch against the finding's file_path
"""
from __future__ import annotations

import fnmatch
import os
import pathlib

import yaml

_DEFAULT_PATH = os.environ.get("DOJO_DASH_SUPPRESSIONS") or str(
    pathlib.Path.cwd() / "config" / "suppressions.yaml"
)


class Suppressions:
    def __init__(self, path: pathlib.Path | str | None = None):
        p = pathlib.Path(path or _DEFAULT_PATH)
        data = yaml.safe_load(p.read_text()) if p.exists() else {}
        self.entries: list[dict] = (data or {}).get("suppressions", [])

    def accepted_risks(self) -> list[dict]:
        return [e for e in self.entries if e.get("kind") == "accepted-risk"]

    @staticmethod
    def finding_haystack(finding: dict) -> str:
        """Text a rule/check id is substring-searched in — so 'AWS-0040' also matches an
        'AVD-AWS-0040' title. Spans the title, tool id, description and CVE ids."""
        vids = " ".join((v.get("vulnerability_id") or "")
                        for v in (finding.get("vulnerability_ids") or []))
        return " ".join((
            finding.get("title", "") or "",
            finding.get("vuln_id_from_tool") or "",
            finding.get("description") or "",
            vids,
        ))

    @staticmethod
    def finding_matches(finding: dict, entry: dict) -> bool:
        """True if `finding` is covered by accepted-risk `entry` (rule/check id + path)."""
        m = entry.get("match", {})
        ids = (m.get("rules") or []) + (m.get("checks") or [])
        paths = m.get("paths") or []
        if ids and not any(i in Suppressions.finding_haystack(finding) for i in ids):
            return False
        if paths:
            fp = finding.get("file_path") or ""
            if not any(fnmatch.fnmatch(fp, p) or p.rstrip("/*") in fp for p in paths):
                return False
        return bool(ids or paths)

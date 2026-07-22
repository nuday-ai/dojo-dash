"""Immediate Critical/High new-finding email alerts, driven by the report poller.

The report server already re-pulls the whole finding set every few minutes to keep the
dashboard warm. That same poll is a natural always-on detector: this module compares each
fresh pull against what it has already seen and, when a *new* Critical/High finding
appears, sends one email. It does NOT re-implement scanning or scheduling — it piggybacks
on the poll the server already runs.

Guarantees the design cares about:
  * Never spam the existing backlog. On the first successful poll it BASELINE-SEEDS every
    currently-qualifying finding as "already seen" and stays silent — only findings that
    show up in *later* polls can alert.
  * Once ever per finding. A finding id is emailed at most once; ids are remembered in
    memory and (optionally) in a state file so a container restart doesn't re-alert.
  * Rate-limited. New findings are batched into a single email, and at most one email is
    sent per ALERT_MIN_INTERVAL_SECONDS window.
  * Opt-in. Does nothing unless recipients AND an SMTP URL are configured.

Configuration (all via environment):
  ALERT_EMAILS               comma/space separated recipients (empty => alerting off)
  ALERT_SMTP_URL             smtp[+tls|+ssl]://user:pass@host:port  (falls back to
                             DD_EMAIL_URL so a DefectDojo stack reuses its own SMTP)
  ALERT_FROM                 From address (falls back to DD_EMAIL_FROM, else smtp user)
  ALERT_SEVERITIES           which severities alert (default "Critical,High")
  ALERT_MIN_INTERVAL_SECONDS min seconds between emails (default 0 => once per poll)
  ALERT_STATE_FILE           optional JSON file to persist seen ids across restarts
  ALERT_LINK_BASE            base URL for finding deep-links (e.g. https://dojo.example.com)
  ALERT_SUBJECT_PREFIX       subject prefix (default "[dojo-dash] ")

Nothing here logs the SMTP password.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage
from urllib.parse import unquote, urlsplit

from .render import _disposition, esc


def _recipients(raw: str) -> list:
    return [a for a in raw.replace(";", ",").replace("\n", ",").replace(" ", ",").split(",") if a]


class Alerter:
    """Stateful across polls. Construct once; call process(rows) after each pull."""

    def __init__(self, env=None):
        env = env if env is not None else os.environ
        self.recipients = _recipients(env.get("ALERT_EMAILS", ""))
        self.smtp_url = env.get("ALERT_SMTP_URL") or env.get("DD_EMAIL_URL") or ""
        self.from_addr = env.get("ALERT_FROM") or env.get("DD_EMAIL_FROM") or ""
        sevs = env.get("ALERT_SEVERITIES", "Critical,High")
        self.severities = {s.strip() for s in sevs.split(",") if s.strip()}
        try:
            self.min_interval = float(env.get("ALERT_MIN_INTERVAL_SECONDS", "0"))
        except ValueError:
            self.min_interval = 0.0
        self.state_file = env.get("ALERT_STATE_FILE", "")
        self.link_base = (env.get("ALERT_LINK_BASE", "") or "").rstrip("/")
        self.subject_prefix = env.get("ALERT_SUBJECT_PREFIX", "[dojo-dash] ")

        self.enabled = bool(self.recipients and self.smtp_url)
        self.seen: set = set()
        self.pending: dict = {}      # finding_id -> row, awaiting a send (deduped)
        self.last_sent = 0.0
        self.primed = False          # has the boot baseline been recorded?

        # A persisted state file means we already have a memory of what's been alerted,
        # so skip baseline seeding and alert on anything not in it (incl. downtime).
        if self.state_file:
            loaded = self._load_state()
            if loaded is not None:
                self.seen = loaded
                self.primed = True

        if self.enabled:
            self._log(f"alerting on {sorted(self.severities)} to {len(self.recipients)} "
                      f"recipient(s) via {urlsplit(self.smtp_url).hostname}"
                      f"{' (state persisted)' if self.state_file else ''}")

    # --- state persistence (best-effort) -------------------------------------
    def _load_state(self):
        try:
            with open(self.state_file) as fh:
                return set(json.load(fh).get("seen", []))
        except FileNotFoundError:
            return None
        except Exception as exc:  # noqa: BLE001 — corrupt/unreadable => fall back to baseline
            self._log(f"could not read state file ({exc}); baseline-seeding instead")
            return None

    def _persist(self):
        if not self.state_file:
            return
        try:
            tmp = self.state_file + ".tmp"
            with open(tmp, "w") as fh:
                # Cap the stored set so the file can't grow unbounded over years.
                json.dump({"seen": sorted(self.seen)[-20000:]}, fh)
            os.replace(tmp, self.state_file)
        except Exception as exc:  # noqa: BLE001
            self._log(f"could not write state file ({exc})")

    # --- the poll hook -------------------------------------------------------
    def _qualifying(self, rows) -> list:
        """Open (active, non-duplicate, non-accepted, non-FP) findings at an alert severity."""
        return [f for f in rows
                if f.get("severity") in self.severities and _disposition(f) == "Open"
                and f.get("finding_id") is not None]

    def process(self, rows, now: float = None):
        """Call after each successful pull. Emails newly-appeared C/H findings, once."""
        if not self.enabled or rows is None:
            return
        now = time.time() if now is None else now
        current = self._qualifying(rows)
        ids = {f["finding_id"] for f in current}

        if not self.primed:  # first poll: remember the backlog, stay silent
            self.seen |= ids
            self.primed = True
            self._persist()
            return

        for f in current:  # queue anything not already handled or queued
            fid = f["finding_id"]
            if fid not in self.seen and fid not in self.pending:
                self.pending[fid] = f
        if not self.pending or (now - self.last_sent) < self.min_interval:
            return  # nothing new, or still inside the rate-limit window (keep pending)

        batch = list(self.pending.values())
        try:
            self._send(batch)
        except Exception as exc:  # noqa: BLE001 — keep pending & retry next poll; never mark seen
            self._log(f"send failed ({exc}); will retry next poll")
            return
        self.seen.update(self.pending)
        self.pending.clear()
        self.last_sent = now
        self._persist()
        self._log(f"emailed {len(batch)} new finding(s) to {len(self.recipients)} recipient(s)")

    # --- email ---------------------------------------------------------------
    def _finding_link(self, f) -> str:
        return f"{self.link_base}/finding/{f['finding_id']}" if self.link_base else ""

    def _bodies(self, findings):
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings = sorted(findings, key=lambda f: (order.get(f.get("severity"), 9),
                                                   f.get("product") or ""))
        text_lines, html_rows = [], []
        for f in findings:
            sev = f.get("severity", "?")
            title = f.get("title", "") or "(untitled)"
            prod = f.get("product", "") or "?"
            env = f.get("environment", "") or ""
            link = self._finding_link(f)
            loc = f"{prod}{f' · {env}' if env else ''}"
            text_lines.append(f"  [{sev}] {title}\n      {loc}" + (f"\n      {link}" if link else ""))
            titlecell = (f'<a href="{esc(link)}">{esc(title)}</a>' if link else esc(title))
            html_rows.append(
                f'<tr><td style="padding:6px 10px;font-weight:700">{esc(sev)}</td>'
                f'<td style="padding:6px 10px">{titlecell}<br>'
                f'<span style="color:#667">{esc(loc)}</span></td></tr>')
        text = ("New findings requiring attention:\n\n" + "\n\n".join(text_lines) + "\n")
        html = (
            '<div style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;font-size:14px">'
            f'<p><b>{len(findings)}</b> new finding(s) requiring attention:</p>'
            '<table style="border-collapse:collapse;font-size:13px">'
            + "".join(html_rows) + "</table></div>")
        return text, html

    def _send(self, findings):
        n = len(findings)
        sevs = ", ".join(sorted({f.get("severity", "?") for f in findings},
                                key=lambda s: {"Critical": 0, "High": 1}.get(s, 9)))
        text, html = self._bodies(findings)
        msg = EmailMessage()
        msg["Subject"] = f"{self.subject_prefix}{n} new {sevs} finding{'' if n == 1 else 's'}"
        u = urlsplit(self.smtp_url)
        user = unquote(u.username) if u.username else None
        pw = unquote(u.password) if u.password else None
        msg["From"] = self.from_addr or user or "dojo-dash@localhost"
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")

        scheme = (u.scheme or "smtp").lower()
        implicit_ssl = scheme in ("smtps", "smtp+ssl")
        # "submission" (RFC 6409, port 587) is what DefectDojo's DD_EMAIL_URL commonly uses.
        starttls = scheme in ("smtp+tls", "smtp+starttls", "submission")
        host = u.hostname or "localhost"
        port = u.port or (465 if implicit_ssl else 587 if starttls else 25)
        ctx = ssl.create_default_context()
        if implicit_ssl:
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as s:
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as s:
                if starttls:
                    s.starttls(context=ctx)
                if user:
                    s.login(user, pw)
                s.send_message(msg)

    def _log(self, m: str):
        sys.stderr.write(f"dojo-dash alerts: {m}\n")

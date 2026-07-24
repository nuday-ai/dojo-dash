"""Critical/High new-finding email alerts, driven by the report poller.

The report server already re-pulls the whole finding set every few minutes to keep the
dashboard warm. That same poll is a natural always-on detector: this module compares each
fresh pull against what it has already seen and, when a *new* Critical/High finding
appears, sends one email. It does NOT re-implement scanning or scheduling — it piggybacks
on the poll the server already runs.

Guarantees the design cares about:
  * Never spam the existing backlog. On the first poll against an empty dedup store it
    BASELINE-SEEDS every currently-qualifying finding as "already seen" and stays silent —
    only findings that show up in *later* polls can alert.
  * Once ever per finding. A finding id is emailed at most once; ids are remembered in a
    pluggable dedup store (memory / local file / MongoDB) so a container restart doesn't
    re-alert.
  * Quiet hours. Emails are only sent inside a configurable local-time window (e.g.
    08:00–20:00 America/Los_Angeles). Findings that appear off-hours are held (never
    dropped) and flushed when the window next opens.
  * Rate-limited. New findings are batched into a single email, and at most one email is
    sent per min_interval window.
  * Opt-in. Does nothing unless recipients AND an SMTP URL are configured.

Configuration comes from the ``alerts:`` block of reports.yaml (passed in as ``config``)
with environment variables taking precedence for overrides and secrets. Resolution order
for every setting is: **env var > config yaml > built-in default**.

  alerts:
    enabled: true                     # master switch (still needs recipients + SMTP)
    severities: [Critical, High]
    recipients: []                    # ALERT_EMAILS env overrides
    subject_prefix: "[dojo-dash] "    # ALERT_SUBJECT_PREFIX env overrides
    link_base: ""                     # ALERT_LINK_BASE env overrides
    min_interval_seconds: 0           # ALERT_MIN_INTERVAL_SECONDS env overrides
    quiet_hours:
      tz: America/Los_Angeles         # ALERT_HOURS_TZ env overrides
      start: 8                        # inclusive local hour; ALERT_HOURS_START env overrides
      end: 20                         # exclusive local hour; ALERT_HOURS_END env overrides
      gate_all: true                  # false => Critical bypasses the window (pages 24/7)
    dedup:
      backend: mongodb                # memory | file | mongodb; ALERT_DEDUP_BACKEND overrides
      mongo:
        uri: mongodb://report-dedup:27017   # ALERT_DEDUP_MONGO_URI env overrides
        database: dojo_dash
        collection: alerted_findings
      file:
        path: ""                      # ALERT_STATE_FILE env overrides

Env-only secrets: ALERT_SMTP_URL (falls back to DD_EMAIL_URL). Nothing here logs the
SMTP password.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import sys
import time
from datetime import datetime
from email.message import EmailMessage
from urllib.parse import unquote, urlsplit

try:  # stdlib on 3.9+, but needs the IANA db (the tzdata dep provides it on slim images)
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None

from .render import _disposition, esc

_PRIMED_MARKER = "__primed__"  # sentinel doc so an empty backlog still counts as primed


def _recipients(raw: str) -> list:
    return [a for a in raw.replace(";", ",").replace("\n", ",").replace(" ", ",").split(",") if a]


def _log(m: str):
    sys.stderr.write(f"dojo-dash alerts: {m}\n")


# --------------------------------------------------------------------------- dedup stores
class _MemoryStore:
    """No durability — every boot baseline-seeds the current backlog."""
    backend = "memory"

    def load(self):
        return set(), False

    def save(self, seen, new_ids):
        pass


class _FileStore:
    """A local JSON file. Survives a container restart only if the path is on a volume."""
    backend = "file"

    def __init__(self, path):
        self.path = path

    def load(self):
        try:
            with open(self.path) as fh:
                return set(json.load(fh).get("seen", [])), True
        except FileNotFoundError:
            return set(), False
        except Exception as exc:  # noqa: BLE001 — corrupt/unreadable => fall back to baseline
            _log(f"could not read state file ({exc}); baseline-seeding instead")
            return set(), False

    def save(self, seen, new_ids):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as fh:
                # Cap the stored set so the file can't grow unbounded over years.
                json.dump({"seen": sorted(seen)[-20000:]}, fh)
            os.replace(tmp, self.path)
        except Exception as exc:  # noqa: BLE001
            _log(f"could not write state file ({exc})")


class _MongoStore:
    """A MongoDB collection of {_id: finding_id}. Durable across container restarts; on
    this deployment the backing volume is reset by an ASG instance refresh, which simply
    re-baselines (safe — never double-sends). Raises on connect failure so the Alerter can
    fall back to memory."""
    backend = "mongodb"

    def __init__(self, uri, database, collection):
        import pymongo  # lazy: only required for this backend
        self._client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        self._client.admin.command("ping")  # fail fast if unreachable
        self.coll = self._client[database][collection]

    def load(self):
        seen, primed = set(), False
        for d in self.coll.find({}, {"_id": 1}):
            primed = True
            if d["_id"] != _PRIMED_MARKER:
                seen.add(d["_id"])
        return seen, primed

    def save(self, seen, new_ids):
        import pymongo
        ops = [pymongo.UpdateOne({"_id": _PRIMED_MARKER}, {"$set": {"_id": _PRIMED_MARKER}},
                                 upsert=True)]
        ops += [pymongo.UpdateOne({"_id": i}, {"$set": {"_id": i}}, upsert=True)
                for i in new_ids]
        try:
            self.coll.bulk_write(ops, ordered=False)
        except Exception as exc:  # noqa: BLE001 — a failed persist just risks a re-send later
            _log(f"could not write dedup store ({exc})")


def _make_store(dedup_cfg: dict, env) -> object:
    """Build the configured dedup store, falling back to memory on any error."""
    backend = (env.get("ALERT_DEDUP_BACKEND") or dedup_cfg.get("backend") or "").lower()
    # Back-compat: a bare ALERT_STATE_FILE (and no explicit backend) means the file backend.
    if not backend:
        backend = "file" if env.get("ALERT_STATE_FILE") else "memory"
    if backend == "memory":
        return _MemoryStore()
    if backend == "file":
        path = env.get("ALERT_STATE_FILE") or (dedup_cfg.get("file") or {}).get("path") or ""
        if not path:
            _log("file dedup backend selected but no path set; using memory")
            return _MemoryStore()
        return _FileStore(path)
    if backend == "mongodb":
        m = dedup_cfg.get("mongo") or {}
        uri = env.get("ALERT_DEDUP_MONGO_URI") or m.get("uri") or "mongodb://localhost:27017"
        try:
            return _MongoStore(uri, m.get("database", "dojo_dash"),
                               m.get("collection", "alerted_findings"))
        except Exception as exc:  # noqa: BLE001
            _log(f"mongodb dedup store unavailable ({exc}); using memory this run")
            return _MemoryStore()
    _log(f"unknown dedup backend '{backend}'; using memory")
    return _MemoryStore()


# --------------------------------------------------------------------------- alerter
def _as_bool(v, default):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _as_int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


class Alerter:
    """Stateful across polls. Construct once; call process(rows) after each pull."""

    def __init__(self, config=None, env=None):
        env = env if env is not None else os.environ
        cfg = config or {}

        # recipients / SMTP (secrets stay env-first)
        env_recips = _recipients(env.get("ALERT_EMAILS", ""))
        self.recipients = env_recips or list(cfg.get("recipients") or [])
        self.smtp_url = env.get("ALERT_SMTP_URL") or env.get("DD_EMAIL_URL") or ""
        self.from_addr = (env.get("ALERT_FROM") or cfg.get("from")
                          or env.get("DD_EMAIL_FROM") or "")

        sevs = env.get("ALERT_SEVERITIES")
        if sevs:
            self.severities = {s.strip() for s in sevs.split(",") if s.strip()}
        else:
            self.severities = set(cfg.get("severities") or ["Critical", "High"])

        self.min_interval = float(_as_int(
            env.get("ALERT_MIN_INTERVAL_SECONDS"), cfg.get("min_interval_seconds", 0)))
        self.link_base = (env.get("ALERT_LINK_BASE") or cfg.get("link_base") or "").rstrip("/")
        self.subject_prefix = (env.get("ALERT_SUBJECT_PREFIX")
                               if env.get("ALERT_SUBJECT_PREFIX") is not None
                               else cfg.get("subject_prefix", "[dojo-dash] "))

        # quiet hours
        qh = cfg.get("quiet_hours") or {}
        self.hours_tz = env.get("ALERT_HOURS_TZ") or qh.get("tz") or ""
        self.hours_start = _as_int(env.get("ALERT_HOURS_START"), qh.get("start", 0))
        self.hours_end = _as_int(env.get("ALERT_HOURS_END"), qh.get("end", 24))
        self.gate_all = _as_bool(env.get("ALERT_HOURS_GATE_ALL"), qh.get("gate_all", True))
        # Hours gating is active only when a tz is configured AND the window is a real
        # subset of the day. tz=="" or 0..24 means "always allowed".
        self._tzinfo = None
        self.hours_active = False
        if self.hours_tz and not (self.hours_start == 0 and self.hours_end == 24):
            if ZoneInfo is None:
                _log("zoneinfo unavailable; quiet-hours gating disabled (sending anytime)")
            else:
                try:
                    self._tzinfo = ZoneInfo(self.hours_tz)
                    self.hours_active = True
                except Exception as exc:  # noqa: BLE001
                    _log(f"bad quiet_hours tz '{self.hours_tz}' ({exc}); gating disabled")

        # master switch + runtime state
        self.enabled = bool(_as_bool(cfg.get("enabled"), True)
                            and self.recipients and self.smtp_url)
        self.pending: dict = {}      # finding_id -> row, awaiting a send (deduped)
        self.last_sent = 0.0

        # dedup store: load prior memory, else baseline on the first poll
        self.store = _make_store(cfg.get("dedup") or {}, env)
        self.seen, self.primed = self.store.load()

        if self.enabled:
            window = (f", quiet hours {self.hours_start:02d}:00-{self.hours_end:02d}:00 "
                      f"{self.hours_tz}{' (all severities)' if self.gate_all else ' (High only)'}"
                      if self.hours_active else "")
            _log(f"alerting on {sorted(self.severities)} to {len(self.recipients)} "
                 f"recipient(s) via {urlsplit(self.smtp_url).hostname} "
                 f"(dedup: {self.store.backend}{', primed' if self.primed else ''}){window}")

    # --- quiet hours ---------------------------------------------------------
    def _may_send(self, sev, now: float) -> bool:
        """Is `sev` allowed to email at `now`? Outside the window only Critical may pass,
        and only when gate_all is off."""
        if not self.hours_active:
            return True
        hour = datetime.fromtimestamp(now, self._tzinfo).hour
        if self.hours_start <= self.hours_end:
            in_window = self.hours_start <= hour < self.hours_end
        else:  # overnight window, e.g. 20..6
            in_window = hour >= self.hours_start or hour < self.hours_end
        if in_window:
            return True
        return sev == "Critical" and not self.gate_all

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

        if not self.primed:  # first poll against an empty store: remember backlog, stay silent
            self.seen |= ids
            self.primed = True
            self.store.save(self.seen, ids)
            return

        for f in current:  # queue anything not already handled or queued
            fid = f["finding_id"]
            if fid not in self.seen and fid not in self.pending:
                self.pending[fid] = f
        if not self.pending or (now - self.last_sent) < self.min_interval:
            return  # nothing new, or still inside the rate-limit window (keep pending)

        # Quiet hours: only send findings allowed to email right now; hold the rest.
        sendable = {fid: f for fid, f in self.pending.items()
                    if self._may_send(f.get("severity"), now)}
        if not sendable:
            return  # everything is held until the window opens; keep pending

        batch = list(sendable.values())
        try:
            self._send(batch)
        except Exception as exc:  # noqa: BLE001 — keep pending & retry next poll; never mark seen
            _log(f"send failed ({exc}); will retry next poll")
            return
        new_ids = set(sendable)
        self.seen |= new_ids
        for fid in new_ids:
            self.pending.pop(fid, None)
        self.last_sent = now
        self.store.save(self.seen, new_ids)
        held = f"; holding {len(self.pending)} for quiet hours" if self.pending else ""
        _log(f"emailed {len(batch)} new finding(s) to {len(self.recipients)} recipient(s){held}")

    # --- email ---------------------------------------------------------------
    def _finding_link(self, f) -> str:
        return f"{self.link_base}/finding/{f['finding_id']}" if self.link_base else ""

    def _bodies(self, findings):
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
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

    def _log(self, m: str):  # retained for back-compat with any external callers
        _log(m)

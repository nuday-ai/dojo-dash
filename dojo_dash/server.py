"""Live-hosted DefectDojo reports — the served counterpart of render.py.

A tiny stdlib HTTP server (no framework) that renders the reports declared in
reports.yaml. It has no authentication of its own: run it behind a reverse proxy that
handles auth (nginx, oauth2-proxy, an ALB with Cognito, …), exactly as you'd front the
DefectDojo UI. See docs/deployment.md.

Freshness model: a single background thread re-pulls the whole finding set from the
DefectDojo API every REPORT_REFRESH_INTERVAL seconds (default 300 = 5 min) and caches
it. Page requests are ALWAYS served from that warm cache, so they never block on the
API. Report pages carry a `<meta http-equiv="refresh">` so an open dashboard reloads
itself on the same cadence.

That same poll doubles as an alert detector: if ALERT_EMAILS + an SMTP URL are set, each
pull is diffed against what's been seen and newly-appeared Critical/High findings trigger
one email (once ever per finding). See alerts.py.

Routes:
  GET /report             -> the first configured report (the dashboard home)
  GET /report/<name>      -> that report, rendered from the cached finding set
  GET /report/findings    -> filterable / paginated findings browser
  GET /report/refresh     -> force a synchronous re-pull, then 302 back
  GET /report/health      -> cheap 200 for a proxy/target-group health check

Config (environment):
  DD_URL                    base URL of the DefectDojo API
  DD_API_TOKEN              \\ auth for the API (token preferred); or
  DD_ADMIN_USER/PASSWORD    /  admin creds, exchanged for a token. Never logged.
  DOJO_DASH_CONFIG          path to reports.yaml (default /app/config/reports.yaml)
  REPORT_PORT               listen port (default 8091)
  REPORT_REFRESH_INTERVAL   background pull + page auto-reload cadence, seconds (default 300)
  REPORT_PAGE_SIZE          DefectDojo API page size (default 1000)
  ALERT_*                   see alerts.py for the email-alert configuration
"""
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, urlencode

from . import __version__
from .render import (
    page, esc, load_config, render_report, _normalize_api,
    _chip, _dim, _disposition, _disp_chip, _repo_cell, _finding_title, _link_ctx,
    DISPOSITIONS,
)

PORT = int(os.environ.get("REPORT_PORT", "8091"))
# How often the background poller re-pulls, and how often an open page reloads itself.
# Back-compat: honor the old REPORT_CACHE_TTL if REPORT_REFRESH_INTERVAL is unset.
REFRESH_INTERVAL = int(os.environ.get("REPORT_REFRESH_INTERVAL")
                       or os.environ.get("REPORT_CACHE_TTL") or "300")
RETRY_INTERVAL = 15  # re-pull sooner than the full interval after a failed pull (e.g. DD still booting)
# Big API page size => far fewer round-trips per pull (the main latency source).
# DefectDojo caps it to its own max if this is larger; that's fine.
PAGE_SIZE = int(os.environ.get("REPORT_PAGE_SIZE", "1000"))

CFG = load_config()

# --- live-data cache (background poller) -----------------------------------
# One normalized finding set serves every report, so cache it globally. A single
# daemon thread refreshes it on a fixed cadence; requests only ever read the cache,
# so no user request blocks on the (multi-second) API pull.
_lock = threading.Lock()
_cache = {"rows": None, "when": ""}

# Immediate C/H alerting, built once in main() so it keeps its dedup state across polls.
# None => alerting is off (also the case when ALERT_EMAILS / SMTP aren't configured).
ALERTER = None


def _fetch_rows():
    from .dojo_api import Dojo  # imported lazily so /health works with no creds
    dojo = Dojo(os.environ.get("DD_URL"))
    return _normalize_api(dojo, CFG["product_type"], page_size=PAGE_SIZE,
                          env_exclude=set(CFG.get("environment_exclude") or []))


def _store(rows):
    with _lock:
        _cache.update(rows=rows, when=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def _snapshot():
    with _lock:
        return _cache["rows"], _cache["when"]


def _maybe_alert(rows):
    """Feed a fresh pull to the alerter (no-op if alerting is off). Never let an alert
    failure disturb serving — the data is already cached."""
    if ALERTER is None:
        return
    try:
        ALERTER.process(rows)
    except BaseException as e:  # noqa: BLE001
        sys.stderr.write(f"alert processing failed: {e}\n")


def _refresh_once():
    """Pull, cache, and run alerting. Shared by the poller and the manual refresh."""
    rows = _fetch_rows()
    _store(rows)
    _maybe_alert(rows)


def _poller_loop():
    """Re-pull forever on a fixed cadence; retry sooner if a pull fails (DD booting)."""
    while True:
        try:
            _refresh_once()
            delay = REFRESH_INTERVAL
        except BaseException as e:  # noqa: BLE001 — keep serving the last good data
            sys.stderr.write(f"report_server refresh failed: {e}\n")
            delay = min(RETRY_INTERVAL, REFRESH_INTERVAL)
        time.sleep(delay)


# --- HTML ------------------------------------------------------------------
def _now_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _human_interval(sec: int) -> str:
    return f"{sec // 60} min" if sec >= 60 and sec % 60 == 0 else f"{sec}s"


def _with_meta_refresh(doc: str, seconds: int) -> str:
    """Make the page reload itself every `seconds` (client-side auto-refresh)."""
    return doc.replace("<head>", f'<head><meta http-equiv="refresh" content="{int(seconds)}">', 1)


def render_error(code: int, msg_html: str) -> str:
    body = (f'<section><h2>Error {code}</h2><p class="muted">{msg_html}</p>'
            '<p style="margin-top:14px"><a href="/report">← Back to report</a></p></section>')
    return page(CFG, title=f"Error {code}", subtitle="", body=body, gen=_now_stamp(), live="")


def render_warming() -> str:
    """Shown only in the brief window after boot before the first pull completes."""
    body = ('<section><h2>Loading latest data…</h2>'
            '<p class="muted">Pulling the current findings from DefectDojo. '
            'This page refreshes automatically.</p></section>')
    doc = page(CFG, title="Loading…", subtitle="", body=body, gen=_now_stamp(), live="")
    return _with_meta_refresh(doc, 5)


def _report_path(cfg: dict) -> str:
    reps = cfg.get("reports", [])
    return f'/report/{reps[0]["name"]}' if reps else "/report"


def _nav_tabs(cfg: dict, current, counts=None) -> str:
    """The primary navigation: one tab per configured report, then the findings browser.

    Every destination the dashboard has is on this strip, which is what lets the old
    per-page action buttons go away — "Browse & filter all findings" is now the findings
    tab, and the findings page's "Back to report" is just the report tab. `current` is a
    report name, or the literal "findings" on the browser page.

    The findings tab deliberately lands on `?disposition=Open` and counts only the OPEN
    findings. Landing on the unfiltered set showed accepted/mitigated/false-positive
    findings interleaved with live ones, which reads as a far bigger backlog than there
    is. The other dispositions are one select away (and the Disposition dropdown shows
    "Open" pre-selected, so the filter is visible rather than hidden). `counts` is
    (open, total) when known.
    """
    def tab(href: str, inner: str, on: bool, title: str = "") -> str:
        cls = "nav-tab on" if on else "nav-tab"
        cur = ' aria-current="page"' if on else ""
        t = f' title="{esc(title)}"' if title else ""
        return f'<a class="{cls}"{cur}{t} href="{href}">{inner}</a>'

    tabs = [tab(f'/report/{esc(r["name"])}',
                esc(r.get("nav_label") or r.get("title") or r["name"]),
                r.get("name") == current)
            for r in cfg.get("reports", [])]
    # Rendered as plain text, exactly like the report tabs — no count pill and no
    # icon. The count is still carried in the tooltip, so the information survives
    # without the tab advertising a number the other tabs don't have.
    hint = ""
    if counts:
        open_n, total_n = counts
        hint = f"{open_n:,} open of {total_n:,} findings — other dispositions via the filter"
    tabs.append(tab("/report/findings?disposition=Open", "Open findings",
                    current == "findings", hint))
    return ('<nav class="navbar" aria-label="Reports"><div class="nav-tabs">'
            + "".join(tabs) + "</div></nav>")


def _counts(rows) -> tuple:
    """(open, total) over the whole snapshot — drives the findings tab's count pill."""
    return sum(1 for f in rows if _disposition(f) == "Open"), len(rows)


def inject_bar(doc: str, cfg: dict, when: str, *, auto_refresh: bool = True,
               current=None, counts=None) -> str:
    """Insert the tab strip below the header, and the freshness + actions into its corner.

    Two zones, each with one job: the strip below the header is navigation only, and the
    header's top-right holds everything about the *state of the data* (how fresh it is,
    force a re-pull, leave for DefectDojo). Previously both were crammed into one bordered
    bar, which wrapped the freshness note onto its own line at common widths.
    """
    freshness = (f'auto-refreshes every {_human_interval(REFRESH_INTERVAL)}' if auto_refresh
                 else f'refreshes in the background every {_human_interval(REFRESH_INTERVAL)}')
    # Force-refresh: pulls fresh data from DefectDojo now instead of waiting for the
    # background cadence. `next` is set client-side to the CURRENT url (filters/page
    # preserved); the click shows a spinning, disabled state until the redirect lands.
    refresh = (
        '<a class="nav-refresh" id="refreshBtn" href="/report/refresh" '
        'title="Pull the latest findings from DefectDojo now">'
        '<span class="ref-ico" aria-hidden="true">&#8635;</span> Refresh</a>'
        '<script>(function(){var b=document.getElementById("refreshBtn");if(!b)return;'
        'b.href="/report/refresh?next="+encodeURIComponent(location.pathname+location.search);'
        'b.addEventListener("click",function(){b.classList.add("busy");'
        'b.setAttribute("aria-busy","true");b.lastChild.textContent=" Refreshing\\u2026";});})();</script>'
    )
    # Return-to-DefectDojo is root-relative by default so it reuses the same proxy
    # session; override with branding.home_url.
    b = cfg.get("branding") or {}
    home_url = esc(b.get("home_url", "/"))
    home_label = esc(b.get("home_label", "Return to DefectDojo"))
    dojo_btn = f'<a class="nav-dojo" href="{home_url}"><span>&#8617;</span> {home_label}</a>'
    # Tell the header a tab strip follows, so it drops its own bottom rule (see .tabbed).
    doc = doc.replace('<header class="rpt">', '<header class="rpt tabbed">', 1)
    doc = doc.replace('<div class="hdr-right">',
                      f'<div class="hdr-right"><div class="hdr-actions">{refresh}{dojo_btn}</div>', 1)
    # Overwrite the page template's "generated at" stamp. On a served page the meaningful
    # timestamp is the DATA's (when the cache was pulled), not the render's — and carrying
    # both here and in the nav read as two clocks a few inches apart. The static CLI
    # renderer never calls this, so it keeps the generation stamp.
    stamp = (f'<div class="stamp">data as of <b>{esc(when)}</b><br>{freshness}</div>')
    doc = re.sub(r'<div class="stamp">.*?</div>', lambda _: stamp, doc, count=1, flags=re.S)
    return doc.replace("</header>", "</header>\n" + _nav_tabs(cfg, current, counts), 1)


# --- filterable / paginated findings "show" page ---------------------------
FINDINGS_PER_PAGE = 25


def _first(params: dict, key: str, default: str = "") -> str:
    v = params.get(key)
    return (v[0] if v else default).strip()


def _age_days(created: str, now: datetime):
    """Precise age in (fractional) days from the finding's `created` timestamp, or None.
    DefectDojo's `age` field floors to whole days; this keeps sub-day resolution."""
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86400)


def _fmt_age(days) -> str:
    """Compact, human age: '<1h' / '7h' / '2.3d' / '45d'."""
    if days is None:
        return ""
    if days < 1 / 24:
        return "&lt;1h"
    if days < 1:
        return f"{int(round(days * 24))}h"
    if days < 10:
        return f"{days:.1f}d"
    return f"{int(round(days))}d"


def _disp_cell(f: dict) -> str:
    """Disposition as a COLOURED chip (same palette the reports' disposition matrix uses:
    Open red, Accepted slate, Mitigated green, False-positive purple), so a mixed list is
    scannable — plain text made resolved rows look identical to live ones. For accepted
    findings that matched a registry entry, append a 'Justification' link that opens the
    modal (kept out of the table to stay readable)."""
    d = _disposition(f)
    disp = _disp_chip(d) if d else "—"
    if f.get("justification"):
        disp += (
            f' · <a class="just-link" href="#" data-ra="{esc(f.get("ra", ""))}" '
            f'data-title="{esc(f.get("title", ""))}" data-just="{esc(f["justification"])}" '
            f'data-owner="{esc(f.get("owner", ""))}" '
            f'data-trigger="{esc(f.get("re_review_trigger", ""))}">Justification</a>'
        )
    return disp


# The justification modal (one per page; the .just-link data-* attributes fill it).
MODAL_HTML = """
<div class="modal-backdrop" id="jmodal" hidden>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="jm-title">
    <div class="modal-head"><span class="modal-ra" id="jm-ra"></span>
      <button class="modal-x" id="jm-x" type="button" aria-label="Close">&times;</button></div>
    <h3 class="modal-title" id="jm-title"></h3>
    <p class="modal-body" id="jm-body"></p>
    <div class="modal-meta" id="jm-meta"></div>
  </div>
</div>
<script>
(function(){
  var bd=document.getElementById('jmodal');if(!bd)return;
  function txt(el,v){el.textContent=v||'';}
  function open(a){
    txt(document.getElementById('jm-ra'),a.getAttribute('data-ra'));
    txt(document.getElementById('jm-title'),a.getAttribute('data-title')||'Risk acceptance justification');
    txt(document.getElementById('jm-body'),a.getAttribute('data-just'));
    var owner=a.getAttribute('data-owner')||'',trig=a.getAttribute('data-trigger')||'';
    var m=document.getElementById('jm-meta');m.textContent='';
    if(owner){var o=document.createElement('div');var b=document.createElement('b');b.textContent='Owning team: ';o.appendChild(b);o.appendChild(document.createTextNode(owner));m.appendChild(o);}
    if(trig){var t=document.createElement('div');t.style.marginTop='4px';var b2=document.createElement('b');b2.textContent='Re-review when: ';t.appendChild(b2);t.appendChild(document.createTextNode(trig));m.appendChild(t);}
    bd.hidden=false;
  }
  document.addEventListener('click',function(e){
    var a=e.target.closest?e.target.closest('.just-link'):null;
    if(a){e.preventDefault();open(a);return;}
    if(e.target===bd||e.target.id==='jm-x')bd.hidden=true;
  });
  document.addEventListener('keydown',function(e){if(e.key==='Escape')bd.hidden=true;});
})();
</script>
"""


def render_findings_page(rows, when, params, cfg) -> str:
    """A live, filterable, paginated view of the finding set (25/page). Every table
    in the reports links here pre-filtered; each row links into its Dojo finding.
    base="" -> root-relative links reuse the proxy session."""
    ctx = _link_ctx(rows, cfg, "")
    sevs = cfg.get("severities", [])
    f_product = _first(params, "product")
    f_env = _first(params, "environment")
    f_scan = _first(params, "scan_type")
    f_scan_detail = _first(params, "scan_detail")
    f_sev = _first(params, "severity")
    f_disp = _first(params, "disposition")
    f_q = _first(params, "q")
    try:
        page_n = max(1, int(_first(params, "page", "1")))
    except ValueError:
        page_n = 1

    def keep(f):
        return (
            (not f_product or f.get("product") == f_product)
            and (not f_env or _dim(f, "environment", cfg) == f_env)
            and (not f_scan or _dim(f, "scan_type", cfg) == f_scan)
            and (not f_scan_detail or _dim(f, "scan_detail", cfg) == f_scan_detail)
            and (not f_sev or f.get("severity") == f_sev)
            and (not f_disp or _disposition(f) == f_disp)
            and (not f_q or f_q.lower() in (f.get("title", "") or "").lower())
        )

    now = datetime.now(timezone.utc)
    filtered = [f for f in rows if keep(f)]
    ages = {id(f): _age_days(f.get("created"), now) for f in filtered}

    rank = {s: i for i, s in enumerate(sevs)}
    disp_rank = {d: i for i, d in enumerate(DISPOSITIONS)}

    def _agekey(f):
        a = ages.get(id(f))
        return a if a is not None else -1.0

    # sortable column id -> (key function, default-descending-on-first-click?)
    sort_cols = {
        "severity":    (lambda f: rank.get(f["severity"], 9), False),
        "title":       (lambda f: (f.get("title") or "").lower(), False),
        "product":     (lambda f: (f.get("product") or "").lower(), False),
        "scan_detail": (lambda f: _dim(f, "scan_detail", cfg), False),
        "environment": (lambda f: _dim(f, "environment", cfg), False),
        "disposition": (lambda f: disp_rank.get(_disposition(f), 9), False),
        "age":         (_agekey, True),
        "discovered":  (lambda f: f.get("discovered_date") or "", True),
        # A finding is accepted OR mitigated (never both) — one "Resolved" date coalesces them.
        "resolved":    (lambda f: f.get("accepted_date") or f.get("mitigated_date") or "", True),
    }
    raw_sort = _first(params, "sort")
    sort_col = raw_sort.lstrip("-")
    if sort_col not in sort_cols:
        sort_col, raw_sort = "", ""
    sort_desc = raw_sort.startswith("-")

    # Default order (no explicit sort): severity, then oldest-first. With a sort column,
    # a STABLE sort on top of that base keeps severity/age as the tiebreak.
    matched = sorted(filtered, key=lambda f: (rank.get(f["severity"], 9), -_agekey(f)))
    if sort_col:
        matched.sort(key=sort_cols[sort_col][0], reverse=sort_desc)
    total = len(matched)
    pages = max(1, (total + FINDINGS_PER_PAGE - 1) // FINDINGS_PER_PAGE)
    page_n = min(page_n, pages)
    start = (page_n - 1) * FINDINGS_PER_PAGE
    window = matched[start:start + FINDINGS_PER_PAGE]

    # filter form (selects populated from the whole snapshot, current value preserved)
    products = sorted({f["product"] for f in rows if f.get("product")})
    envs = sorted({_dim(f, "environment", cfg) for f in rows})
    scan_types = cfg.get("scan_type_order") or sorted({_dim(f, "scan_type", cfg) for f in rows})
    scan_details = cfg.get("scan_detail_order") or sorted({_dim(f, "scan_detail", cfg) for f in rows})

    def opts(values, cur):
        out = ['<option value="">All</option>']
        for v in values:
            out.append(f'<option value="{esc(v)}"{" selected" if v == cur else ""}>{esc(v)}</option>')
        return "".join(out)

    # Auto-filtering: any select change (or Enter/blur on the text box) submits the
    # form — no explicit Filter button. A <noscript> submit keeps it usable without JS.
    form = (
        '<form class="filters" method="get" action="/report/findings">'
        f'<label>Repository<select name="product">{opts(products, f_product)}</select></label>'
        f'<label>Scan type<select name="scan_type">{opts(scan_types, f_scan)}</select></label>'
        f'<label>Scan<select name="scan_detail">{opts(scan_details, f_scan_detail)}</select></label>'
        f'<label>Environment<select name="environment">{opts(envs, f_env)}</select></label>'
        f'<label>Severity<select name="severity">{opts(sevs, f_sev)}</select></label>'
        f'<label>Disposition<select name="disposition">{opts(list(DISPOSITIONS), f_disp)}</select></label>'
        f'<label>Title contains<input type="text" name="q" value="{esc(f_q)}" placeholder="search…"></label>'
        f'<input type="hidden" name="sort" value="{esc(raw_sort)}">'
        '<div class="btns"><a class="btn clear" href="/report/findings">Clear</a>'
        '<noscript><button class="btn" type="submit">Filter</button></noscript></div>'
        '</form>'
        '<script>(function(){var f=document.querySelector("form.filters");if(!f)return;'
        'f.addEventListener("change",function(){f.submit();});'
        'var q=f.querySelector("input[name=q]"),t;'
        'if(q){q.addEventListener("input",function(){clearTimeout(t);'
        't=setTimeout(function(){f.submit();},450);});'
        'try{sessionStorage.getItem("qfocus")==="1"&&(q.focus(),'
        'q.setSelectionRange(q.value.length,q.value.length));}catch(e){}'
        'q.addEventListener("focus",function(){try{sessionStorage.setItem("qfocus","1");}catch(e){}});'
        'f.addEventListener("submit",function(){try{if(document.activeElement!==q)'
        'sessionStorage.removeItem("qfocus");}catch(e){}});}})();</script>'
    )

    def _dt(v):
        return f'<td class="dt">{esc(v)}</td>' if v else '<td class="dt none">—</td>'

    # Clickable, server-side sort headers, preserving current filters in each link.
    base_q = {k: v for k, v in {
        "product": f_product, "environment": f_env, "scan_type": f_scan,
        "scan_detail": f_scan_detail, "severity": f_sev, "disposition": f_disp, "q": f_q,
    }.items() if v}

    def _th(label, col, cls=""):
        if sort_col == col:
            nxt = col if sort_desc else "-" + col
            arrow = " ↓" if sort_desc else " ↑"
            active = " on"
        else:
            nxt = ("-" + col) if sort_cols[col][1] else col
            arrow, active = "", ""
        url = "/report/findings?" + urlencode({**base_q, "sort": nxt})
        klass = ("srt " + cls).strip() + active
        return f'<th class="{klass}"><a href="{esc(url)}">{esc(label)}{arrow}</a></th>'

    thead = ("<tr>" + _th("Sev", "severity") + _th("Finding", "title") + _th("Repo", "product")
             + _th("Scan", "scan_detail") + _th("Environment", "environment")
             + _th("Disposition", "disposition") + _th("Age", "age", "num")
             + _th("Discovered", "discovered") + _th("Resolved", "resolved") + "</tr>")

    if window:
        trs = "".join(
            f'<tr><td>{_chip(f["severity"], None)}</td><td>{_finding_title(ctx, f)}</td>'
            f'<td>{_repo_cell(ctx, f["product"])}</td><td>{esc(_dim(f, "scan_detail", cfg))}</td>'
            f'<td>{esc(_dim(f, "environment", cfg))}</td>'
            f'<td>{_disp_cell(f)}</td>'
            f'<td class="num dt">{_fmt_age(ages.get(id(f)))}</td>'
            f'{_dt(f.get("discovered_date"))}'
            f'{_dt(f.get("accepted_date") or f.get("mitigated_date"))}</tr>'
            for f in window)
        table = (f'<div class="tblwrap"><table class="list"><thead>{thead}</thead>'
                 f'<tbody>{trs}</tbody></table></div>')
    else:
        table = '<p class="muted">No findings match these filters.</p>'

    def page_url(p):
        q = {k: v for k, v in {"product": f_product, "environment": f_env, "scan_type": f_scan,
                               "scan_detail": f_scan_detail, "severity": f_sev,
                               "disposition": f_disp, "q": f_q, "sort": raw_sort, "page": p}.items()
             if v not in ("", None)}
        return "/report/findings?" + urlencode(q)

    prev_ = (f'<a href="{esc(page_url(page_n - 1))}">← Prev</a>' if page_n > 1
             else '<span class="dis">← Prev</span>')
    next_ = (f'<a href="{esc(page_url(page_n + 1))}">Next →</a>' if page_n < pages
             else '<span class="dis">Next →</span>')
    lo = 0 if total == 0 else start + 1
    hi = min(start + FINDINGS_PER_PAGE, total)
    pager = (f'<div class="pager">{prev_}'
             f'<span class="info">Showing {lo}–{hi} of {total} · page {page_n}/{pages}</span>{next_}</div>')

    body = f'<section>{form}{table}{pager}</section>' + MODAL_HTML
    doc = page(cfg, title="Findings", subtitle="Filter live findings — open each in DefectDojo.",
               body=body, gen=_now_stamp(), live="")
    # auto_refresh=False: this page is NOT meta-refreshed (a reload mid-triage would
    # discard the filters/page you're on), so the strip says so. The tab pill counts the
    # whole snapshot, not `total` above — that one is already filtered.
    return inject_bar(doc, cfg, when, auto_refresh=False, current="findings",
                      counts=_counts(rows))


# --- server ----------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = f"dojo-dash/{__version__}"

    def _send(self, code: int, body, ctype: str = "text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")  # always reflect the latest cache
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path.rstrip("/") or "/"

        if path in ("/report/health", "/health", "/healthz"):
            return self._send(200, "ok", "text/plain; charset=utf-8")

        # Force-refresh: re-pull from DefectDojo NOW (synchronous, a few seconds — the
        # server is threaded so other requests keep serving the warm cache), then 302
        # back to where the user was. `next` is constrained to /report* to avoid an
        # open redirect; a failed pull keeps the last good data and still returns.
        if path == "/report/refresh":
            nxt = _first(parse_qs(urlsplit(self.path).query), "next", _report_path(CFG))
            if not nxt.startswith("/report"):
                nxt = _report_path(CFG)
            try:
                _refresh_once()
            except BaseException as e:  # noqa: BLE001 — keep the last good cache on failure
                sys.stderr.write(f"manual refresh failed: {e}\n")
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Filterable/paginated findings browser — intercept before the generic
        # "/report/<name>" report lookup (else "findings" is treated as a report name).
        if path == "/report/findings":
            rows, when = _snapshot()
            if rows is None:
                return self._send(200, render_warming())
            params = parse_qs(urlsplit(self.path).query)
            try:
                doc = render_findings_page(rows, when, params, CFG)
            except Exception as e:  # noqa: BLE001
                return self._send(500, render_error(500, f"Render error: {esc(e)}"))
            return self._send(200, doc)

        # The configured reports — served at /report, / (direct hit), or /report/<name>.
        reps = CFG.get("reports", [])
        report = None
        if path in ("/report", "/"):
            report = reps[0] if reps else None
        elif path.startswith("/report/"):
            name = path[len("/report/"):]
            report = next((r for r in reps if r["name"] == name), None)
        if report is None:
            return self._send(404, render_error(404, "Not found."))

        rows, when = _snapshot()
        if rows is None:  # first pull not done yet — auto-reloads in a few seconds
            return self._send(200, render_warming())
        try:
            # base="" -> tables link root-relative (/report/findings, /finding/<id>,
            # /product/<id>), reusing the same proxy session as the DefectDojo UI.
            doc = inject_bar(render_report(report, rows, CFG, base=""), CFG, when,
                             current=report["name"], counts=_counts(rows))
            doc = _with_meta_refresh(doc, REFRESH_INTERVAL)
        except Exception as e:  # noqa: BLE001 — render over cached rows shouldn't fail
            return self._send(500, render_error(500, f"Render error: {esc(e)}"))
        return self._send(200, doc)

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, fmt, *args):  # to stderr, no bodies/headers (never creds)
        sys.stderr.write(f"dojo-dash {self.address_string()} - {fmt % args}\n")


def main():
    global ALERTER
    from .alerts import Alerter
    # Driven by the `alerts:` block of reports.yaml (env vars override); a no-op unless
    # recipients + an SMTP URL are configured.
    ALERTER = Alerter(CFG.get("alerts"))
    # Background poller keeps the cache warm so every request is served instantly.
    threading.Thread(target=_poller_loop, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stderr.write(
        f"dojo-dash listening on :{PORT} (refresh {REFRESH_INTERVAL}s, page {PAGE_SIZE}) "
        f"-> {os.environ.get('DD_URL', '(default)')}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

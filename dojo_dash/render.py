"""Render the reports declared in reports.yaml against the LIVE DefectDojo API into
self-contained HTML (no external assets) under $DOJO_DASH_OUT/<name>.html.

This is the config-as-code replacement for the built-in DefectDojo dashboard: severity ×
environment / repository heatmaps, KPI cards, a documented risk-acceptance register, an
open-findings table, and a SOC 2 / CASA evidence view — all driven by reports.yaml.

    dojo-dash render                          # every report
    dojo-dash render --report posture --open
    dojo-dash render --findings-json dump.json   # offline / testing (no API needed)

Auth: DD_URL + DD_API_TOKEN, or DD_ADMIN_USER/DD_ADMIN_PASSWORD. See dojo_api.py.
The --findings-json dump is a JSON list of the normalized rows this module emits
(one per finding); use it to render without API access (e.g. from an ORM export).
"""
import argparse
import base64
import html
import json
import os
import pathlib
import sys
import webbrowser
from collections import Counter, defaultdict
from datetime import date, datetime

import requests
import yaml

# Config + output locations are env-overridable so both the container (a mounted
# /app/config) and a local checkout (./config) work with no arguments.
def _default_config() -> pathlib.Path:
    for cand in (os.environ.get("DOJO_DASH_CONFIG"),
                 "/app/config/reports.yaml",
                 str(pathlib.Path.cwd() / "config" / "reports.yaml")):
        if cand and pathlib.Path(cand).exists():
            return pathlib.Path(cand)
    # Nothing found — return the explicit/env path (or the cwd default) so the eventual
    # read raises a clear FileNotFoundError that names the path it looked for.
    return pathlib.Path(os.environ.get("DOJO_DASH_CONFIG")
                        or str(pathlib.Path.cwd() / "config" / "reports.yaml"))


CONFIG = _default_config()
OUT_DIR = pathlib.Path(os.environ.get("DOJO_DASH_OUT")
                       or str(pathlib.Path.cwd() / "output" / "reports"))


def _sibling(name: str, env_var: str) -> pathlib.Path:
    """A config file that sits next to reports.yaml (dojo_sla.yaml, suppressions.yaml),
    overridable by an env var."""
    return pathlib.Path(os.environ.get(env_var) or (CONFIG.parent / name))

# Severity palette (bg for chips / heatmap tint).
SEV_COLOR = {
    "Critical": "#7b1fa2", "High": "#c62828", "Medium": "#ef6c00",
    "Low": "#f9a825", "Info": "#607d8b",
}

# Generic default brand mark — a security shield around a monitoring pulse, in the
# dashboard's accent tone on its panel background. Inlined as a data URI so it needs no
# served asset and survives in any published-to-DefectDojo HTML. Override it per-deploy
# with `branding.logo` in reports.yaml (a path or a data: URI). Used for BOTH the
# favicon and the header badge.
_DEFAULT_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<rect width="64" height="64" rx="14" fill="#0f1622"/>'
    '<path d="M32 8 L52 16 V32 C52 44 43 52 32 56 C21 52 12 44 12 32 V16 Z" '
    'fill="none" stroke="#5cc2d6" stroke-width="3"/>'
    '<polyline points="19,34 27,34 31,23 37,43 41,34 45,34" fill="none" '
    'stroke="#eaf0f7" stroke-width="3" stroke-linejoin="round" stroke-linecap="round"/>'
    '</svg>'
)


def _svg_data_uri(svg: str) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()


_DEFAULT_LOGO_URI = _svg_data_uri(_DEFAULT_LOGO_SVG)
_MIME = {".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg",
         ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}


def _logo_uri(spec) -> str:
    """Resolve `branding.logo` to a data/URL usable in <img src>. Accepts a data: URI
    or http(s) URL (used verbatim) or a file path (read + base64-inlined, relative to
    reports.yaml). Falls back to the built-in default on anything missing/unreadable."""
    if not spec:
        return _DEFAULT_LOGO_URI
    s = str(spec)
    if s.startswith(("data:", "http://", "https://")):
        return s
    try:
        p = pathlib.Path(s)
        if not p.is_absolute():
            p = CONFIG.parent / p
        raw = p.read_bytes()
        if p.suffix.lower() == ".svg":
            return _svg_data_uri(raw.decode("utf-8"))
        mime = _MIME.get(p.suffix.lower(), "application/octet-stream")
        return f"data:{mime};base64," + base64.b64encode(raw).decode()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"_logo_uri: could not load '{s}' ({exc}); using default\n")
        return _DEFAULT_LOGO_URI


_DEFAULT_FOOTER = ('Rendered by <code>dojo-dash</code> from <code>reports.yaml</code>, '
                   'live from the DefectDojo API')


def _branding(cfg) -> dict:
    """Header/favicon/footer branding, all from the optional `branding:` config block
    with generic defaults so an unbranded deploy still looks finished."""
    b = (cfg or {}).get("branding") or {}
    return {
        "logo": _logo_uri(b.get("logo")),
        "eyebrow": esc(b.get("eyebrow", "Security")),
        "logo_alt": esc(b.get("logo_alt") or b.get("eyebrow") or "dojo-dash"),
        "footer": b.get("footer") or _DEFAULT_FOOTER,
        "home_url": b.get("home_url", "/"),
        "home_label": b.get("home_label", "Return to DefectDojo"),
    }


SCOPE_KEYS = ("active", "duplicate", "risk_accepted", "false_p", "out_of_scope")


def load_config(path=None) -> dict:
    """Parse reports.yaml. Shared by the CLI (main) and the live report server so both
    interpret the same definitions. `path` overrides the env/default location."""
    global CONFIG
    if path:
        CONFIG = pathlib.Path(path)
    return yaml.safe_load(CONFIG.read_text())


# --------------------------------------------------------------------------- data
def _normalize_api(dojo, pt_name: str, page_size: int = 100) -> list:
    """Pull every finding under the product type and resolve product / environment /
    engagement names via the id maps (one paginate per collection, joined in memory).

    page_size sets the API page limit: a larger value means far fewer round-trips
    (the served report server passes a big one to keep first-load latency down)."""
    pt = next((p for p in dojo.paginate("product_types", limit=page_size) if p["name"] == pt_name), None)
    if not pt:
        sys.exit(f"Product type '{pt_name}' not found in DefectDojo.")
    products = {p["id"]: p["name"] for p in dojo.paginate("products", prod_type=pt["id"], limit=page_size)}
    engagements = {e["id"]: e for e in dojo.paginate("engagements", product__prod_type=pt["id"], limit=page_size)}
    envs = {e["id"]: e["name"] for e in dojo.paginate("development_environments", limit=page_size)}
    tests = {t["id"]: t for t in dojo.paginate("tests", limit=page_size)
             if t.get("engagement") in engagements}

    # Accepted-risk registry, for attaching the justification to each accepted finding
    # (first matching entry wins — mirrors apply_risk_acceptance.py's claim order).
    # BEST-EFFORT: never let a missing suppressions module/file break the whole poll —
    # the report must still load (just without justification links) if it's unavailable.
    accepted_entries, _match = [], None
    try:
        from .suppressions import Suppressions
        accepted_entries = Suppressions().accepted_risks()
        _match = Suppressions.finding_matches
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"_normalize_api: justifications unavailable ({exc})\n")

    # finding_id -> acceptance date. The date isn't on the finding; it lives on the
    # risk_acceptance object (decision_date). BEST-EFFORT — never break the poll.
    ra_date = {}
    try:
        for ra in dojo.paginate("risk_acceptance", limit=page_size):
            d = (ra.get("decision_date") or ra.get("created") or "")[:10]
            for af in ra.get("accepted_findings", []):
                fid = af.get("id") if isinstance(af, dict) else af
                if fid is not None:
                    ra_date[fid] = d
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"_normalize_api: acceptance dates unavailable ({exc})\n")

    rows = []
    for f in dojo.paginate("findings", test__engagement__product__prod_type=pt["id"], limit=page_size):
        # Drop Info/Informational findings entirely — they don't belong on this
        # dashboard (no column, no count, no alert). Filtering here is the single
        # choke point every report + the alerter consume, so excluding them once
        # removes them everywhere and shrinks the rows we normalize/serve.
        if (f.get("severity") or "") in ("Info", "Informational"):
            continue
        t = tests.get(f.get("test")) or {}
        eng = engagements.get(t.get("engagement")) or {}
        row = {
            "severity": f.get("severity"),
            "product": products.get(eng.get("product"), "?"),
            "environment": envs.get(t.get("environment"), ""),
            "engagement": eng.get("name", "?"),
            "title": f.get("title", ""),
            "age_days": f.get("age"),
            # IDs for deep-linking into the DefectDojo UI (finding / product pages).
            "finding_id": f.get("id"),
            "product_id": eng.get("product"),
            "engagement_id": t.get("engagement"),
            "active": bool(f.get("active")),
            "duplicate": bool(f.get("duplicate")),
            "risk_accepted": bool(f.get("risk_accepted")),
            "false_p": bool(f.get("false_p")),
            "out_of_scope": bool(f.get("out_of_scope")),
            "is_mitigated": bool(f.get("is_mitigated")),
            # Was a derived heuristic (not active/accepted/FP) that mis-counted
            # out-of-scope & duplicate findings; use DefectDojo's real flag.
            "mitigated": bool(f.get("is_mitigated")),
            # Lifecycle dates (date-only). `date` = discovery; `mitigated` = the
            # mitigation timestamp (distinct from the bool above); accepted date from
            # the risk_acceptance object. Blank when not applicable.
            "discovered_date": (f.get("date") or "")[:10],
            "mitigated_date": (f.get("mitigated") or "")[:10],
            "accepted_date": ra_date.get(f.get("id"), ""),
            # Full creation timestamp — lets the show page compute a PRECISE age
            # (hours / fractional days) instead of DefectDojo's whole-day `age`.
            "created": f.get("created") or "",
        }
        if row["risk_accepted"] and _match:
            e = next((en for en in accepted_entries if _match(f, en)), None)
            if e:
                row["ra"] = e["id"]
                row["justification"] = " ".join((e.get("justification") or "").split())
                row["owner"] = e.get("owner", "")
                row["re_review_trigger"] = e.get("re_review_trigger", "")
        rows.append(row)
    return rows


def _in_scope(f: dict, scope: dict) -> bool:
    for k in SCOPE_KEYS:
        if k in scope and bool(f.get(k)) != bool(scope[k]):
            return False
    if scope.get("engagement") and f.get("engagement") != scope["engagement"]:
        return False
    return True


# ------------------------------------------------------------------------- render
def esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _desc(d) -> str:
    """Small explanatory line rendered under a section heading (from reports.yaml)."""
    return f'<p class="muted" style="margin:-2px 0 13px;max-width:78ch">{esc(d)}</p>' if d else ""


# --- text-contrast helpers ---------------------------------------------------
# Pick black or white text per swatch so labels stay readable on ANY background —
# the severity/disposition palette mixes dark (Critical purple, High red) and light
# (Low amber) colors, and the matrix tint blends them over the dark page at varying
# alpha, so a single fixed text color is unreadable on one end or the other.
_TEXT_DARK = "#0d1117"
_TEXT_LIGHT = "#f5f8fc"
_PAGE_BG = (0x0c, 0x11, 0x19)  # --bg, what a semi-transparent tint cell sits over


def _hex_rgb(h: str) -> tuple:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _rel_lum(rgb: tuple) -> float:
    def chan(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (chan(x) for x in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a: tuple, b: tuple) -> float:
    la, lb = _rel_lum(a), _rel_lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _blend(fg: tuple, bg: tuple, alpha: float) -> tuple:
    return tuple(round(f * alpha + b * (1 - alpha)) for f, b in zip(fg, bg))


def _ideal_text(bg_rgb: tuple) -> str:
    """Black or white — whichever has higher WCAG contrast against bg_rgb."""
    return _TEXT_DARK if _contrast(bg_rgb, _hex_rgb(_TEXT_DARK)) >= \
        _contrast(bg_rgb, _hex_rgb(_TEXT_LIGHT)) else _TEXT_LIGHT


def _swatch_style(hex_color: str, alpha: float = 1.0) -> str:
    """`background:...;color:...` for a colored swatch, with text auto-contrasted
    against the color as actually rendered (blended over the page bg at `alpha`)."""
    rgb = _hex_rgb(hex_color)
    fg = _ideal_text(_blend(rgb, _PAGE_BG, alpha) if alpha < 1 else rgb)
    bg = f"{hex_color}{int(alpha * 255):02x}" if alpha < 1 else hex_color
    return f"background:{bg};color:{fg}"


def _chip(sev: str, n) -> str:
    c = SEV_COLOR.get(sev, "#888")
    return (f'<span class="chip" style="{_swatch_style(c)}">{esc(sev)}'
            f'{"" if n is None else f" · {n}"}</span>')


def _tint(sev: str, n: int, mx: int) -> str:
    if not n:
        return "background:transparent;color:#5a6878"  # zeros: visible but muted
    c = SEV_COLOR.get(sev, "#888")
    alpha = 0.18 + 0.62 * (n / mx if mx else 1)
    return f"{_swatch_style(c, alpha)};font-weight:700"


# ---------------------------------------------------------------- deep links
# The served report lives at <dojo_host>/report/* behind the SAME ALB as the
# DefectDojo UI, so a root-relative link (base="") like /finding/42 or /product/7
# resolves straight into Dojo under the same Cognito session. The CLI-rendered
# static artifact passes base=<dojo_url> so those links are absolute instead.
def _show_url(base, **filters) -> str:
    """URL of the live, filterable findings 'show' page (served by report_server)."""
    from urllib.parse import urlencode
    qs = urlencode({k: v for k, v in filters.items() if v not in (None, "", [])})
    return f"{base}/report/findings" + (f"?{qs}" if qs else "")


def _dojo_finding_url(base, fid):
    return f"{base}/finding/{fid}" if fid is not None else None


def _dojo_product_url(base, pid):
    return f"{base}/product/{pid}" if pid is not None else None


def _gh_url(cfg: dict, product: str):
    gh = cfg.get("github") or {}
    org, repos = gh.get("org"), (gh.get("repos") or [])
    return f"https://github.com/{org}/{product}" if org and product in repos else None


def _repo_cell(ctx, product: str) -> str:
    """Repo name + small GitHub / DefectDojo deep-link pills. Plain name if ctx is
    None (offline render). ctx = {base, cfg, prod_ids}."""
    name = f'<span class="repo">{esc(product)}</span>'
    if not ctx:
        return esc(product)
    pills = []
    gh = _gh_url(ctx["cfg"], product)
    if gh:
        pills.append(f'<a class="rlink" href="{esc(gh)}" target="_blank" rel="noopener" '
                     f'title="Open {esc(product)} on GitHub">GitHub&#8599;</a>')
    du = _dojo_product_url(ctx["base"], ctx["prod_ids"].get(product))
    if du:
        pills.append(f'<a class="rlink" href="{esc(du)}" target="_blank" rel="noopener" '
                     f'title="View {esc(product)} in DefectDojo">Dojo&#8599;</a>')
    return name + "".join(pills)


def _bucket_of(engagement: str, cfg: dict, map_key: str, default_key: str, default: str) -> str:
    """Map a finding's DefectDojo engagement to a labelled bucket via a config table
    (engagement -> [engagement names]). Shared by the coarse `scan_type` (Static/DAST/
    Runtime) and the finer `scan_detail` (Static/DAST/AWS/EKS/Images) dimensions."""
    for cat, engs in (cfg.get(map_key) or {}).items():
        if engagement in engs:
            return cat
    return cfg.get(default_key, default)


def _scan_type_of(engagement: str, cfg: dict) -> str:
    """Coarse discipline — Static / DAST / Runtime — from config `scan_types`."""
    return _bucket_of(engagement, cfg, "scan_types", "scan_type_default", "Static")


def _scan_detail_of(engagement: str, cfg: dict) -> str:
    """Exact scan — Static / DAST / AWS (CSPM) / EKS (KSPM) / Container images — from
    config `scan_detail`. Splits the Runtime bucket into its individual live scanners."""
    return _bucket_of(engagement, cfg, "scan_detail", "scan_detail_default", "Static")


def _dim(f: dict, dim: str, cfg: dict):
    v = f.get(dim, "")
    if dim == "environment":
        return cfg.get("environment_labels", {}).get(v, v or "Unspecified")
    if dim == "scan_type":
        return _scan_type_of(f.get("engagement", ""), cfg)
    if dim == "scan_detail":
        return _scan_detail_of(f.get("engagement", ""), cfg)
    return v or "?"


def _dim_order(dim: str, values: set, cfg: dict) -> list:
    if dim == "environment":
        order = cfg.get("environment_order", [])
        labels = cfg.get("environment_labels", {})
        seen, out = set(), []
        for raw in order:
            lbl = labels.get(raw, raw)
            if lbl in values and lbl not in seen:
                out.append(lbl); seen.add(lbl)
        out += sorted(v for v in values if v not in seen)
        return out
    if dim in ("scan_type", "scan_detail"):
        order = cfg.get("scan_type_order" if dim == "scan_type" else "scan_detail_order", [])
        seen, out = set(), []
        for c in order:
            if c in values and c not in seen:
                out.append(c); seen.add(c)
        out += sorted(v for v in values if v not in seen)
        return out
    return sorted(values)


def _matrix_data(findings, dim, sevs, cfg, universe=None):
    grid = defaultdict(lambda: defaultdict(int))
    for f in findings:
        grid[_dim(f, dim, cfg)][f["severity"]] += 1
    # Show every known row (even all-zero ones) so the table doesn't collapse when
    # a repo/environment has no OPEN findings — `universe` is the full set from the
    # whole finding population; fall back to whatever the open set contains.
    rows = _dim_order(dim, set(grid) | set(universe or ()), cfg)
    used = list(sevs)  # always show every severity column (zeros included)
    mx = max([grid[r][s] for r in rows for s in used] + [1])
    return rows, used, grid, mx


def _cell_tip(sev, n, filters) -> str:
    disp = (filters.get("disposition") or "").lower()
    loc = filters.get("product") or filters.get("environment")
    label = f"{disp} {sev}".strip()
    tip = f"{n} {label} finding{'' if n == 1 else 's'}"
    if loc:
        tip += f" in {loc}"
    return tip + " — click to filter"


def _matrix_cell(ctx, sev, n, mx, filters) -> str:
    """A heatmap cell. Non-zero counts link into the filtered show page (with a
    hover highlight + styled tooltip); zeros render as a muted '0'."""
    if n and ctx:
        url = esc(_show_url(ctx["base"], severity=sev, **filters))
        inner = f'<a href="{url}" data-tip="{esc(_cell_tip(sev, n, filters))}">{n}</a>'
    else:
        inner = str(n)
    return f'<td style="{_tint(sev, n, mx)}">{inner}</td>'


def render_matrix(findings, dim, sevs, cfg, title, ctx=None, desc=None) -> str:
    universe = None
    if dim == "scan_type":
        universe = cfg.get("scan_type_order")            # always show Static/DAST/Runtime
    elif ctx:
        universe = ctx.get("products") if dim == "product" else ctx.get("environments")
    rows, used, grid, mx = _matrix_data(findings, dim, sevs, cfg, universe)
    filt = dim   # cell links carry {product|environment|scan_type: <row>} into the show page

    head = "".join(f"<th>{_chip(s, None)}</th>" for s in used)
    body = []
    for r in rows:
        cells = "".join(_matrix_cell(ctx, s, grid[r].get(s, 0), mx, {filt: r, "disposition": "Open"})
                        for s in used)
        rh = _repo_cell(ctx, r) if dim == "product" else esc(r)
        total = sum(grid[r].values())
        body.append(f'<tr><th class="rh">{rh}</th>{cells}<td class="tot">{total}</td></tr>')
    foot = "".join(f'<td class="tot">{sum(grid[r].get(s,0) for r in rows)}</td>' for s in used)
    grand = sum(sum(grid[r].values()) for r in rows)
    return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}<div class="tblwrap"><table class="matrix">'
            f'<thead><tr><th></th>{head}<th>Total</th></tr></thead>'
            f'<tbody>{"".join(body)}</tbody>'
            f'<tfoot><tr><th class="rh">Total</th>{foot}<td class="tot">{grand}</td></tr></tfoot>'
            f'</table></div></section>')


# Disposition buckets, in priority order — each finding lands in exactly ONE
# (an accepted finding is also inactive/mitigated in DefectDojo, so order matters
# to avoid double-counting). `open` is anything still active and otherwise plain.
DISPOSITIONS = ("Open", "Accepted", "Mitigated", "False-positive")


def _disposition(f: dict) -> str:
    if f.get("risk_accepted"):
        return "Accepted"
    if f.get("false_p"):
        return "False-positive"
    if f.get("is_mitigated") or f.get("mitigated"):
        return "Mitigated"
    if f.get("active") and not f.get("duplicate") and not f.get("out_of_scope"):
        return "Open"
    return ""  # duplicates / other inactive-but-untriaged — not shown


def _disposition_data(findings_all, sevs, rows):
    grid = defaultdict(lambda: defaultdict(int))
    for f in findings_all:
        d = _disposition(f)
        if d in rows:
            grid[d][f["severity"]] += 1
    used = list(sevs)  # always show every severity column (zeros included)
    mx = max([grid[r][s] for r in rows for s in used] + [1])
    return used, grid, mx


def render_disposition(findings_all, sevs, title, rows=None, ctx=None, desc=None) -> str:
    rows = list(rows) if rows else list(DISPOSITIONS)
    used, grid, mx = _disposition_data(findings_all, sevs, rows)
    head = "".join(f"<th>{_chip(s, None)}</th>" for s in used)
    body = []
    for r in rows:
        cells = "".join(_matrix_cell(ctx, s, grid[r].get(s, 0), mx, {"disposition": r})
                        for s in used)
        total = sum(grid[r].values())
        body.append(f'<tr><th class="rh">{esc(r)}</th>{cells}<td class="tot">{total}</td></tr>')
    foot = "".join(f'<td class="tot">{sum(grid[r].get(s,0) for r in rows)}</td>' for s in used)
    grand = sum(sum(grid[r].values()) for r in rows)
    return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}'
            f'<div class="tblwrap"><table class="matrix">'
            f'<thead><tr><th>Disposition</th>{head}<th>Total</th></tr></thead>'
            f'<tbody>{"".join(body)}</tbody>'
            f'<tfoot><tr><th class="rh">Total</th>{foot}<td class="tot">{grand}</td></tr></tfoot>'
            f'</table></div></section>')


# Disposition palette (for the repo × disposition summary chips / heatmap tint).
DISP_COLOR = {"Open": "#c62828", "Accepted": "#607d8b", "Mitigated": "#2e7d32",
              "False-positive": "#8e24aa"}
REPO_SUMMARY_COLS = ("Open", "Accepted", "Mitigated")


def _disp_chip(disp: str) -> str:
    return f'<span class="chip" style="{_swatch_style(DISP_COLOR.get(disp, "#888"))}">{esc(disp)}</span>'


def _disp_tint(disp: str, n: int, mx: int) -> str:
    if not n:
        return "background:transparent;color:#5a6878"
    c = DISP_COLOR.get(disp, "#888")
    alpha = 0.18 + 0.62 * (n / mx if mx else 1)
    return f"{_swatch_style(c, alpha)};font-weight:700"


def _disp_repo_cell(ctx, repo, disp, n, mx) -> str:
    if n and ctx:
        url = esc(_show_url(ctx["base"], product=repo, disposition=disp))
        tip = esc(f"{n} {disp.lower()} finding{'' if n == 1 else 's'} in {repo} — click to filter")
        inner = f'<a href="{url}" data-tip="{tip}">{n}</a>'
    else:
        inner = str(n)
    return f'<td style="{_disp_tint(disp, n, mx)}">{inner}</td>'


def render_repo_summary(findings_all, cfg, title, ctx=None, desc=None) -> str:
    """Repository × disposition (open / accepted / mitigated) — same heatmap styling as
    the matrices; accepted counts carry the documented justification (see the show page)."""
    cols = REPO_SUMMARY_COLS
    grid = defaultdict(lambda: defaultdict(int))
    for f in findings_all:
        d = _disposition(f)
        if d in cols:
            grid[f.get("product", "?")][d] += 1
    repos = sorted(set(grid) | (set(ctx.get("products", ())) if ctx else set()))
    mx = max([grid[r][c] for r in repos for c in cols] + [1])
    head = "".join(f"<th>{_disp_chip(c)}</th>" for c in cols)
    body = []
    for r in repos:
        cells = "".join(_disp_repo_cell(ctx, r, c, grid[r].get(c, 0), mx) for c in cols)
        total = sum(grid[r].get(c, 0) for c in cols)
        body.append(f'<tr><th class="rh">{_repo_cell(ctx, r)}</th>{cells}<td class="tot">{total}</td></tr>')
    foot = "".join(f'<td class="tot">{sum(grid[r].get(c, 0) for r in repos)}</td>' for c in cols)
    grand = sum(sum(grid[r].get(c, 0) for c in cols) for r in repos)
    return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}<div class="tblwrap"><table class="matrix">'
            f'<thead><tr><th>Repository</th>{head}<th>Total</th></tr></thead>'
            f'<tbody>{"".join(body)}</tbody>'
            f'<tfoot><tr><th class="rh">Total</th>{foot}<td class="tot">{grand}</td></tr></tfoot>'
            f'</table></div></section>')


# ---------------------------------------------------------- SOC 2 / CASA evidence
def _sla_windows():
    """Per-severity SLA windows (days) + enforce flags from config/dojo_sla.yaml.
    Best-effort: a missing file degrades the section to 'not configured' rather than
    breaking the whole report (mirrors the justification attachment in _normalize_api)."""
    try:
        c = yaml.safe_load(_sibling("dojo_sla.yaml", "DOJO_DASH_SLA").read_text()) or {}
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"_sla_windows: unavailable ({exc})\n")
        c = {}
    win = {k.capitalize(): v for k, v in (c.get("windows") or {}).items()}
    enf = {k.capitalize(): bool(v) for k, v in (c.get("enforce") or {}).items()}
    return win, enf


def _pct_style(pct: int) -> str:
    col = "#2e7d32" if pct >= 100 else "#ef6c00" if pct >= 90 else "#c62828"
    return f"color:{col};font-weight:700"


def render_sla_compliance(findings_all, cfg, title, ctx=None, desc=None) -> str:
    """Open findings vs their per-severity SLA window (config/dojo_sla.yaml): how many are
    still within SLA vs breached, and the within-SLA %. Evidence for SOC 2 CC7.1 — that
    findings are remediated on a defined cadence, not left to rot."""
    win, enf = _sla_windows()
    sevs = [s for s in cfg.get("severities", []) if s in win]
    if not sevs:
        return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}'
                '<p class="muted">SLA windows not configured (config/dojo_sla.yaml).</p></section>')
    body, tot_open, tot_within, tot_breach = [], 0, 0, 0
    for s in sevs:
        opens = [f for f in findings_all if f["severity"] == s and _disposition(f) == "Open"]
        n_open = len(opens)
        n_breach = sum(1 for f in opens if (f.get("age_days") or 0) > win[s])
        n_within = n_open - n_breach
        pct = 100 if n_open == 0 else round(100 * n_within / n_open)
        tot_open += n_open; tot_within += n_within; tot_breach += n_breach
        bstyle = "color:#c62828;font-weight:700" if n_breach else "color:#5a6878"
        note = "" if enf.get(s, True) else ' <span class="muted">· not enforced</span>'
        rh = (f'{_chip(s, None)} <span class="muted">&le;{win[s]}d</span>{note}')
        body.append(
            f'<tr><th class="rh">{rh}</th><td class="num">{n_open}</td>'
            f'<td class="num">{n_within}</td><td class="num" style="{bstyle}">{n_breach}</td>'
            f'<td class="num" style="{_pct_style(pct)}">{pct}%</td></tr>')
    gpct = 100 if tot_open == 0 else round(100 * tot_within / tot_open)
    foot = (f'<tr class="grand"><th class="rh">Total</th><td class="num">{tot_open}</td>'
            f'<td class="num">{tot_within}</td><td class="num">{tot_breach}</td>'
            f'<td class="num" style="{_pct_style(gpct)}">{gpct}%</td></tr>')
    return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}<div class="tblwrap"><table class="matrix">'
            '<thead><tr><th>Severity (SLA)</th><th class="num">Open</th><th class="num">Within SLA</th>'
            '<th class="num">Breached</th><th class="num">Within-SLA %</th></tr></thead>'
            f'<tbody>{"".join(body)}</tbody><tfoot>{foot}</tfoot></table></div></section>')


def render_scan_coverage(findings_all, cfg, title, ctx=None, desc=None) -> str:
    """Scanning activity by engagement — which scan classes (SAST/SCA/IaC/secrets CI,
    Continuous, DAST, CSPM, KSPM, image) are exercised, across how many repos and
    environments. Evidence for SOC 2 CC7.1 — breadth of the detection program."""
    eng = defaultdict(lambda: {"repos": set(), "envs": set(), "n": 0})
    for f in findings_all:
        e = eng[f.get("engagement", "?")]
        e["n"] += 1
        if f.get("product"):
            e["repos"].add(f["product"])
        e["envs"].add(_dim(f, "environment", cfg))
    if not eng:
        return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}'
                '<p class="muted">No scanning activity yet.</p></section>')
    rows = []
    for name, d in sorted(eng.items(), key=lambda kv: -kv[1]["n"]):
        link = (f'<a href="{esc(_show_url(ctx["base"], q=name))}">{esc(name)}</a>'
                if ctx else esc(name))
        rows.append(f'<tr><td>{link}</td><td class="num">{len(d["repos"])}</td>'
                    f'<td class="num">{len(d["envs"])}</td><td class="num">{d["n"]}</td></tr>')
    total = sum(d["n"] for d in eng.values())
    return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}<div class="tblwrap"><table class="list">'
            '<thead><tr><th>Engagement (scan class)</th><th class="num">Repos</th>'
            '<th class="num">Environments</th><th class="num">Findings</th></tr></thead>'
            f'<tbody>{"".join(rows)}'
            f'<tr class="grand"><td>Total</td><td class="num">{len(eng)} engagements</td>'
            f'<td class="num"></td><td class="num">{total}</td></tr></tbody></table></div></section>')


# Control -> evidence map. The rows are entirely config-driven (a `control_map:` list in
# reports.yaml), so this generalizes to SOC 2 / ISO 27001 / CASA / any framework. Each
# row's `control` and `evidence` may use {placeholders} that are filled with live counts
# from the finding population, so the map is proof, not just prose.
_CONTROL_COUNT_KEYS = ("total", "accepted", "mitigated", "open_ch", "engagements",
                       "products", "environments")


def _control_counts(findings_all, cfg) -> dict:
    return {
        "total": len(findings_all),
        "accepted": sum(1 for f in findings_all if f.get("risk_accepted")),
        "mitigated": sum(1 for f in findings_all if f.get("mitigated")),
        "open_ch": sum(1 for f in findings_all
                       if _disposition(f) == "Open" and f["severity"] in ("Critical", "High")),
        "engagements": len({f.get("engagement") for f in findings_all if f.get("engagement")}),
        "products": len({f.get("product") for f in findings_all if f.get("product")}),
        "environments": len({_dim(f, "environment", cfg) for f in findings_all}),
    }


def render_control_map(findings_all, cfg, title, ctx=None, desc=None) -> str:
    """The 'proof walk': each configured control -> the live artifact that evidences it.
    Rows come from `control_map:` in reports.yaml; {placeholders} fill from live counts."""
    rows_cfg = cfg.get("control_map") or []
    if not rows_cfg:
        return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}'
                '<p class="muted">No control map configured — add a <code>control_map:</code> '
                'list to reports.yaml.</p></section>')
    counts = _control_counts(findings_all, cfg)

    def fmt(s) -> str:
        # Operator-authored HTML (like the section descriptions), with live-count
        # {placeholders}. A stray literal brace just passes through unformatted.
        s = str(s or "")
        try:
            return s.format(**counts)
        except Exception:  # noqa: BLE001
            return s

    rows = "".join(
        f'<tr><td><span class="chip" style="background:#37474f;color:#fff">'
        f'{esc(r.get("control_id") or r.get("tsc") or "")}</span></td>'
        f'<td>{fmt(r.get("control", ""))}</td><td>{fmt(r.get("evidence", ""))}</td></tr>'
        for r in rows_cfg)
    hdr = esc(cfg.get("control_map_label", "Control"))
    return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}<div class="tblwrap"><table class="list">'
            f'<thead><tr><th>{hdr}</th><th>Control</th><th>Evidence (live artifact)</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></section>')


def render_kpis(findings_all, scope, sevs, ctx=None, desc=None, title=None) -> str:
    open_f = [f for f in findings_all if _in_scope(f, scope)]
    by_sev = defaultdict(int)
    for f in open_f:
        by_sev[f["severity"]] += 1
    accepted = sum(1 for f in findings_all if f.get("risk_accepted"))
    mitigated = sum(1 for f in findings_all if f.get("mitigated"))
    # (label, count, color, show-page filters, tooltip-what)
    cards = [("Open", len(open_f), "#c62828" if len(open_f) else "#2e7d32",
              {"disposition": "Open"}, "all open findings")]
    cards += [(s, by_sev.get(s, 0), SEV_COLOR[s], {"disposition": "Open", "severity": s},
               f"open {s} findings") for s in sevs]
    cards += [("Accepted", accepted, "#455a64", {"disposition": "Accepted"}, "accepted findings"),
              ("Mitigated", mitigated, "#2e7d32", {"disposition": "Mitigated"}, "mitigated findings")]
    items = []
    for lbl, n, c, filt, what in cards:
        inner = (f'<div class="kpi-n" style="color:{c}">{n}</div>'
                 f'<div class="kpi-l">{esc(lbl)}</div>')
        if ctx:
            url = esc(_show_url(ctx["base"], **filt))
            items.append(f'<a class="kpi" style="--bar:{c}" href="{url}" '
                         f'data-tip="View {esc(what)}">{inner}</a>')
        else:
            items.append(f'<div class="kpi" style="--bar:{c}">{inner}</div>')
    head = (f'<h2>{esc(title)}</h2>' if title else "") + _desc(desc)
    return f'<section>{head}<div class="kpis">{"".join(items)}</div></section>'


def render_accepted(findings_all, title, ctx=None) -> str:
    by_prod = defaultdict(int)
    for f in findings_all:
        if f.get("risk_accepted"):
            by_prod[f["product"]] += 1
    if not by_prod:
        return ""

    def _cnt(p, n):
        if not ctx:
            return str(n)
        return f'<a href="{esc(_show_url(ctx["base"], product=p, disposition="Accepted"))}">{n}</a>'
    rows = "".join(f"<tr><td>{_repo_cell(ctx, p)}</td><td class='num'>{_cnt(p, n)}</td></tr>"
                   for p, n in sorted(by_prod.items(), key=lambda x: -x[1]))
    total = sum(by_prod.values())
    return (f'<section><h2>{esc(title)}</h2>'
            '<p class="muted">Findings marked <b>risk-accepted</b> in DefectDojo — each a '
            'documented decision with an owner, justification and re-review trigger '
            '(hover a count on the findings page to read it).</p>'
            f'<div class="tblwrap"><table class="list"><thead><tr><th>Repository</th><th class="num">Accepted</th>'
            f'</tr></thead><tbody>{rows}'
            f'<tr class="grand"><td>Total</td><td class="num">{total}</td></tr></tbody></table></div></section>')


def _finding_title(ctx, f) -> str:
    """Finding title, linked into its DefectDojo finding page when live."""
    t = esc(f["title"])
    if ctx:
        u = _dojo_finding_url(ctx["base"], f.get("finding_id"))
        if u:
            return (f'<a href="{esc(u)}" target="_blank" rel="noopener" '
                    f'title="View in DefectDojo">{t}</a>')
    return t


# group_by dimensions that the paginated /report/findings page accepts as a filter,
# so each summary row can deep-link straight to its slice instead of inlining thousands
# of rows into the report (that killed page-load time).
_FINDINGS_FILTER_KEYS = {"environment", "scan_type", "scan_detail", "product", "severity", "disposition"}


def render_findings(findings, group_by, sevs, cfg, title, ctx=None, desc=None) -> str:
    """A *summary* of the open findings grouped by `group_by`: one row per group with a
    severity breakdown and a deep link into the paginated /report/findings browser.
    We deliberately do NOT inline every finding — with thousands of rows the report page
    load crawled; the show page is paginated and filterable, so we link there instead."""
    groups = defaultdict(list)
    for f in findings:
        groups[_dim(f, group_by, cfg)].append(f)
    if not findings:
        return (f'<section><h2>{esc(title)}</h2>{_desc(desc)}'
                '<p class="muted">No open findings. 🎉</p></section>')
    filt_key = group_by if group_by in _FINDINGS_FILTER_KEYS else None
    linked = bool(ctx and ctx.get("base") is not None)
    base_filter = (lambda **extra: {**({filt_key: g} if filt_key else {}), **extra})
    rows = []
    for g in _dim_order(group_by, set(groups), cfg):
        fs = groups[g]
        by_sev = Counter(f["severity"] for f in fs)

        def chip_cell(s):
            chip = _chip(s, by_sev[s])
            if not linked:
                return chip
            # Each severity bubble deep-links to the group PLUS that severity
            # (e.g. scan_type=Runtime&severity=Critical), not just the row total.
            u = esc(_show_url(ctx["base"], **base_filter(severity=s)))
            return f'<a class="chiplink" href="{u}" title="Browse {esc(g)} · {esc(s)}">{chip}</a>'

        chips = "".join(chip_cell(s) for s in sevs if by_sev.get(s))
        if linked:
            url = esc(_show_url(ctx["base"], **base_filter()))
            link = f'<a class="btn" href="{url}">Browse {len(fs)} &rarr;</a>'
        else:
            link = f'<span class="count">{len(fs)}</span>'
        rows.append(
            f'<tr><td><b>{esc(g)}</b></td><td class="chips">{chips}</td>'
            f'<td class="num">{len(fs)}</td><td>{link}</td></tr>')
    table = (
        '<div class="tblwrap"><table class="list"><thead><tr>'
        f'<th>{esc(group_by.replace("_", " ").title())}</th><th>By severity</th>'
        '<th class="num">Total</th><th></th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>')
    note = ('<p class="muted">Grouped summary — open a group to browse and filter the '
            'individual findings.</p>')
    return f'<section><h2>{esc(title)}</h2>{_desc(desc)}{note}{table}</section>'


def _link_ctx(findings_all, cfg, base):
    """Context threaded into HTML renderers so tables can deep-link. base=None
    disables all links (offline render); base="" gives root-relative links (the
    served report, behind the same ALB as Dojo); base=<url> gives absolute ones."""
    if base is None:
        return None
    prod_ids, products, environments = {}, set(), set()
    for f in findings_all:
        if f.get("product"):
            products.add(f["product"])
            if f.get("product_id") is not None:
                prod_ids.setdefault(f["product"], f["product_id"])
        environments.add(_dim(f, "environment", cfg))
    return {"base": base, "cfg": cfg, "prod_ids": prod_ids,
            "products": products, "environments": environments}


def render_report(report, findings_all, cfg, live_url=None, base=None) -> str:
    scope = {**cfg.get("open_scope", {}), **(report.get("scope") or {})}
    sevs = cfg.get("severities", ["Critical", "High", "Medium", "Low", "Info"])
    open_f = [f for f in findings_all if _in_scope(f, scope)]
    ctx = _link_ctx(findings_all, cfg, live_url if base is None else base)
    parts = []
    for sec in report.get("sections", []):
        k = sec["kind"]
        desc = sec.get("desc")
        if k == "kpis":
            parts.append(render_kpis(findings_all, scope, sevs, ctx, desc, sec.get("title")))
        elif k == "matrix":
            parts.append(render_matrix(open_f, sec.get("rows", "environment"), sevs, cfg, sec["title"], ctx, desc))
        elif k == "accepted":
            parts.append(render_accepted(findings_all, sec["title"], ctx))
        elif k == "repo-summary":
            parts.append(render_repo_summary(findings_all, cfg, sec["title"], ctx, desc))
        elif k == "disposition":
            parts.append(render_disposition(findings_all, sevs, sec["title"], sec.get("rows"), ctx, desc))
        elif k == "findings":
            parts.append(render_findings(open_f, sec.get("group_by", "environment"), sevs, cfg, sec["title"], ctx, desc))
        elif k == "sla-compliance":
            parts.append(render_sla_compliance(findings_all, cfg, sec["title"], ctx, desc))
        elif k == "scan-coverage":
            parts.append(render_scan_coverage(findings_all, cfg, sec["title"], ctx, desc))
        elif k == "control-map":
            parts.append(render_control_map(findings_all, cfg, sec["title"], ctx, desc))
    gen = datetime.now().strftime("%Y-%m-%d %H:%M")
    return page(cfg, title=esc(report["title"]), subtitle=esc(report.get("subtitle", "")),
                body="\n".join(parts), gen=gen, live=_live_link_html(live_url))


# ------------------------------------------------------------- markdown (job summary)
def _md_esc(s) -> str:
    return str(s if s is not None else "").replace("|", "\\|")


def md_kpis(findings_all, scope, sevs) -> str:
    open_f = [f for f in findings_all if _in_scope(f, scope)]
    by = defaultdict(int)
    for f in open_f:
        by[f["severity"]] += 1
    acc = sum(1 for f in findings_all if f.get("risk_accepted"))
    mit = sum(1 for f in findings_all if f.get("mitigated"))
    cols = ["Open"] + sevs + ["Accepted", "Mitigated"]
    vals = [len(open_f)] + [by.get(s, 0) for s in sevs] + [acc, mit]
    return ("| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n| "
            + " | ".join(str(v) for v in vals) + " |\n")


def md_matrix(findings, dim, sevs, cfg, title) -> str:
    rows, used, grid, _ = _matrix_data(findings, dim, sevs, cfg)
    out = [f"### {title}", "", "| " + dim.replace("_", " ").title() + " | " + " | ".join(used) + " | Total |",
           "|" + "---|" * (len(used) + 2)]
    for r in rows:
        cells = " | ".join(str(grid[r].get(s, 0)) for s in used)
        out.append(f"| {_md_esc(r)} | {cells} | {sum(grid[r].values())} |")
    tot = " | ".join(str(sum(grid[r].get(s, 0) for r in rows)) for s in used)
    out.append(f"| **Total** | {tot} | {sum(sum(grid[r].values()) for r in rows)} |")
    return "\n".join(out) + "\n"


def md_disposition(findings_all, sevs, title, rows=None) -> str:
    rows = list(rows) if rows else list(DISPOSITIONS)
    used, grid, _ = _disposition_data(findings_all, sevs, rows)
    out = [f"### {title}", "", "| Disposition | " + " | ".join(used) + " | Total |",
           "|" + "---|" * (len(used) + 2)]
    for r in rows:
        cells = " | ".join(str(grid[r].get(s, 0)) for s in used)
        out.append(f"| {_md_esc(r)} | {cells} | {sum(grid[r].values())} |")
    tot = " | ".join(str(sum(grid[r].get(s, 0) for r in rows)) for s in used)
    out.append(f"| **Total** | {tot} | {sum(sum(grid[r].values()) for r in rows)} |")
    return "\n".join(out) + "\n"


def md_accepted(findings_all, title) -> str:
    by = defaultdict(int)
    for f in findings_all:
        if f.get("risk_accepted"):
            by[f["product"]] += 1
    if not by:
        return ""
    out = [f"### {title}", "", "| Repository | Accepted |", "|---|---:|"]
    for p, n in sorted(by.items(), key=lambda x: -x[1]):
        out.append(f"| {_md_esc(p)} | {n} |")
    out.append(f"| **Total** | {sum(by.values())} |")
    return "\n".join(out) + "\n"


def md_repo_summary(findings_all, title) -> str:
    cols = REPO_SUMMARY_COLS
    grid = defaultdict(lambda: defaultdict(int))
    for f in findings_all:
        d = _disposition(f)
        if d in cols:
            grid[f.get("product", "?")][d] += 1
    repos = sorted(grid)
    out = [f"### {title}", "", "| Repository | " + " | ".join(cols) + " | Total |",
           "|" + "---|" * (len(cols) + 2)]
    for r in repos:
        cells = " | ".join(str(grid[r].get(c, 0)) for c in cols)
        out.append(f"| {_md_esc(r)} | {cells} | {sum(grid[r].get(c, 0) for c in cols)} |")
    tot = " | ".join(str(sum(grid[r].get(c, 0) for r in repos)) for c in cols)
    out.append(f"| **Total** | {tot} | {sum(sum(grid[r].get(c, 0) for c in cols) for r in repos)} |")
    return "\n".join(out) + "\n"


def md_findings(findings, group_by, sevs, cfg, title) -> str:
    """Grouped severity summary (not every row) — the full detail lives in the paginated
    /report/findings browser; inlining thousands of rows blows the job-summary size limit."""
    groups = defaultdict(list)
    for f in findings:
        groups[_dim(f, group_by, cfg)].append(f)
    if not findings:
        return f"### {title}\n\nNo open findings. 🎉\n"
    hdr = group_by.replace("_", " ").title()
    out = [f"### {title}", "",
           f"| {hdr} | " + " | ".join(sevs) + " | Total |",
           "|---|" + "|".join("---:" for _ in sevs) + "|---:|"]
    for g in _dim_order(group_by, set(groups), cfg):
        by_sev = Counter(f["severity"] for f in groups[g])
        cells = " | ".join(str(by_sev.get(s, 0)) for s in sevs)
        out.append(f"| {_md_esc(g)} | {cells} | {len(groups[g])} |")
    out += ["", "_Browse individual findings in the report's Findings page._", ""]
    return "\n".join(out) + "\n"


def md_sla_compliance(findings_all, cfg, title) -> str:
    win, enf = _sla_windows()
    sevs = [s for s in cfg.get("severities", []) if s in win]
    if not sevs:
        return f"### {title}\n\nSLA windows not configured.\n"
    out = [f"### {title}", "", "| Severity (SLA) | Open | Within SLA | Breached | Within-SLA % |",
           "|---|---:|---:|---:|---:|"]
    to, tw, tb = 0, 0, 0
    for s in sevs:
        opens = [f for f in findings_all if f["severity"] == s and _disposition(f) == "Open"]
        n_open = len(opens)
        n_breach = sum(1 for f in opens if (f.get("age_days") or 0) > win[s])
        n_within = n_open - n_breach
        pct = 100 if n_open == 0 else round(100 * n_within / n_open)
        to += n_open; tw += n_within; tb += n_breach
        out.append(f"| {s} (≤{win[s]}d) | {n_open} | {n_within} | {n_breach} | {pct}% |")
    gpct = 100 if to == 0 else round(100 * tw / to)
    out.append(f"| **Total** | {to} | {tw} | {tb} | {gpct}% |")
    return "\n".join(out) + "\n"


def md_scan_coverage(findings_all, cfg, title) -> str:
    eng = defaultdict(lambda: {"repos": set(), "envs": set(), "n": 0})
    for f in findings_all:
        e = eng[f.get("engagement", "?")]
        e["n"] += 1
        if f.get("product"):
            e["repos"].add(f["product"])
        e["envs"].add(_dim(f, "environment", cfg))
    if not eng:
        return f"### {title}\n\nNo scanning activity yet.\n"
    out = [f"### {title}", "", "| Engagement | Repos | Environments | Findings |",
           "|---|---:|---:|---:|"]
    for name, d in sorted(eng.items(), key=lambda kv: -kv[1]["n"]):
        out.append(f"| {_md_esc(name)} | {len(d['repos'])} | {len(d['envs'])} | {d['n']} |")
    return "\n".join(out) + "\n"


def md_control_map(findings_all, cfg, title) -> str:
    total = len(findings_all)
    accepted = sum(1 for f in findings_all if f.get("risk_accepted"))
    engagements = len({f.get("engagement") for f in findings_all if f.get("engagement")})
    return (f"### {title}\n\n{engagements} scan engagements · {total} findings tracked · "
            f"{accepted} documented risk acceptances. Full control→evidence map in "
            "`docs/SOC2_EVIDENCE.md`.\n")


def _live_link_md(live_url) -> str:
    if not live_url:
        return ""
    return (f"🔗 **[Open the live, always-current report]({live_url.rstrip('/')}/report)** "
            "— behind the same login as DefectDojo.")


def render_report_md(report, findings_all, cfg, live_url=None) -> str:
    scope = {**cfg.get("open_scope", {}), **(report.get("scope") or {})}
    sevs = cfg.get("severities", ["Critical", "High", "Medium", "Low", "Info"])
    open_f = [f for f in findings_all if _in_scope(f, scope)]
    parts = [f"## {report['title']}", "", f"_{report.get('subtitle', '')}_", ""]
    if live_url:
        parts += [_live_link_md(live_url), ""]
    for sec in report.get("sections", []):
        k = sec["kind"]
        if k == "kpis":
            parts.append(md_kpis(findings_all, scope, sevs))
        elif k == "matrix":
            parts.append(md_matrix(open_f, sec.get("rows", "environment"), sevs, cfg, sec["title"]))
        elif k == "accepted":
            parts.append(md_accepted(findings_all, sec["title"]))
        elif k == "repo-summary":
            parts.append(md_repo_summary(findings_all, sec["title"]))
        elif k == "disposition":
            parts.append(md_disposition(findings_all, sevs, sec["title"], sec.get("rows")))
        elif k == "findings":
            parts.append(md_findings(open_f, sec.get("group_by", "environment"), sevs, cfg, sec["title"]))
        elif k == "sla-compliance":
            parts.append(md_sla_compliance(findings_all, cfg, sec["title"]))
        elif k == "scan-coverage":
            parts.append(md_scan_coverage(findings_all, cfg, sec["title"]))
        elif k == "control-map":
            parts.append(md_control_map(findings_all, cfg, sec["title"]))
    return "\n".join(parts)


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="%LOGO%">
<title>{title}</title><style>
:root{{--bg:#0c1119;--panel:#141c28;--panel2:#0f1622;--line:#24303f;--ink:#eaf0f7;
--mut:#8797a9;--accent:#5cc2d6}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
-webkit-font-smoothing:antialiased}}
.num,.matrix td,.matrix .tot,.kpi-n,.list .num{{font-variant-numeric:tabular-nums}}
.wrap{{max-width:1060px;margin:0 auto;padding:0 20px 72px}}
header.rpt{{border-bottom:1px solid var(--line);padding:34px 0 22px;margin-bottom:8px;
display:flex;align-items:flex-end;justify-content:space-between;gap:20px;flex-wrap:wrap}}
.hdr-left{{display:flex;align-items:center;gap:16px}}
.brand-logo{{width:46px;height:46px;border-radius:11px;flex-shrink:0;display:block;
border:1px solid var(--line);box-shadow:0 6px 18px rgba(0,0,0,.35)}}
header.rpt .eyebrow{{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);
font-weight:700;margin:0 0 8px}}
h1{{font-size:27px;line-height:1.15;margin:0;text-wrap:balance;font-weight:800;letter-spacing:-.01em}}
.sub{{color:var(--mut);margin:6px 0 0;max-width:60ch}}
.stamp{{color:var(--mut);font-size:12px;text-align:right;white-space:nowrap}}
.hdr-right{{display:flex;flex-direction:column;align-items:flex-end;gap:12px}}
h2{{font-size:15px;margin:34px 0 12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);
font-weight:700;text-wrap:balance}}
h3{{font-size:14px;margin:20px 0 8px;color:#cfd9e4;font-weight:600}}h3 .count{{color:var(--mut);font-weight:400}}
section{{margin-bottom:8px}}.muted{{color:var(--mut);font-size:13px}}
code{{background:var(--panel);padding:1px 6px;border-radius:5px;font-size:12px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:10px;margin:30px 0 6px}}
.kpi{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 12px;text-align:center;
position:relative;overflow:hidden;transition:border-color .12s,background .12s,transform .12s}}
a.kpi{{display:block;text-decoration:none;color:inherit;cursor:pointer}}
a.kpi:hover{{border-color:var(--accent);background:#12303a;transform:translateY(-1px)}}
.kpi::before{{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--bar,transparent)}}
.kpi-n{{font-size:28px;font-weight:800;line-height:1;letter-spacing:-.02em}}
.kpi-l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin-top:7px}}
table{{border-collapse:separate;border-spacing:0;width:100%;font-size:13px;border:1px solid var(--line);
border-radius:12px;overflow:hidden}}
.tblwrap{{overflow-x:auto}}
.matrix th,.matrix td{{border-bottom:1px solid var(--line);border-right:1px solid var(--line);padding:9px 12px;text-align:center}}
.matrix tr td:last-child,.matrix tr th:last-child{{border-right:0}}
.matrix tbody tr:last-child td,.matrix tbody tr:last-child th{{border-bottom:1px solid var(--line)}}
.matrix .rh{{text-align:left;background:var(--panel2);font-weight:600;white-space:nowrap}}
.matrix .tot{{background:var(--panel2);font-weight:700}}
.matrix thead th,.matrix tfoot td,.matrix tfoot th{{background:var(--panel);font-weight:700}}
.list th,.list td{{border-bottom:1px solid var(--line);padding:8px 12px;text-align:left;vertical-align:top}}
.list tbody tr:last-child td{{border-bottom:0}}
.list thead th{{background:var(--panel);font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}}
.list .num{{text-align:right;white-space:nowrap}}
.list .dt{{white-space:nowrap;font-variant-numeric:tabular-nums;font-size:12px;color:var(--mut)}}
.list .dt.none{{color:#3d4a5c}}
.list th.srt{{cursor:pointer}}.list th.srt a{{color:inherit;text-decoration:none;display:block;white-space:nowrap}}
.list th.srt a:hover{{color:var(--accent)}}.list th.srt.on a{{color:var(--ink)}}
.list .grand td{{font-weight:800;border-top:2px solid var(--line);background:var(--panel2)}}
.chip{{display:inline-block;color:#fff;font-size:10.5px;font-weight:700;padding:2px 9px;border-radius:20px;
white-space:nowrap;letter-spacing:.02em}}.chips .chip{{margin:2px 4px 2px 0}}
.chiplink,.list td a.chiplink{{text-decoration:none;display:inline-block}}
.chiplink .chip{{cursor:pointer;transition:filter .12s ease,transform .12s ease,box-shadow .12s ease}}
.chiplink:hover .chip,.chiplink:focus-visible .chip{{filter:brightness(1.18);transform:translateY(-1px);
box-shadow:0 2px 6px rgba(0,0,0,.35)}}
.foot{{color:#5f6f80;font-size:12px;margin-top:44px;border-top:1px solid var(--line);padding-top:14px}}
a{{color:var(--accent)}}
.repo{{font-weight:600}}
.rlink{{display:inline-block;font-size:10px;font-weight:600;color:var(--accent);text-decoration:none;
border:1px solid var(--line);border-radius:6px;padding:0 6px;margin-left:6px;white-space:nowrap;
vertical-align:middle;line-height:18px}}
.rlink:hover{{border-color:var(--accent);background:#12303a}}
.matrix td a{{color:inherit;text-decoration:none;display:block;margin:-9px -12px;padding:9px 12px}}
.matrix td a:hover{{background:#12303a;outline:1px solid var(--accent);outline-offset:-1px}}
.list td a{{color:var(--accent);text-decoration:none}}.list td a:hover{{text-decoration:underline}}
.list tbody tr{{transition:background .1s}}.list tbody tr:hover{{background:#12212f}}
/* styled floating tooltip (JS-positioned so it never clips inside scroll areas) */
.tip{{position:fixed;transform:translate(-50%,-100%);background:#0b1220;color:var(--ink);
border:1px solid var(--accent);border-radius:8px;padding:6px 10px;font-size:12px;font-weight:500;
white-space:nowrap;pointer-events:none;opacity:0;transition:opacity .1s;z-index:100;
box-shadow:0 8px 24px rgba(0,0,0,.5)}}
/* single-report nav bar (report page + show page) */
.navbar{{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;
margin:20px 0 4px;padding:11px 14px;border:1px solid var(--line);border-radius:12px;background:var(--panel2)}}
.nav-left,.nav-right{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
.nav-btn{{display:inline-flex;align-items:center;gap:7px;text-decoration:none;font-weight:700;font-size:13.5px;
padding:9px 16px;border-radius:9px;border:1px solid var(--line);color:var(--ink);background:var(--panel);
transition:border-color .12s,background .12s,transform .12s}}
.nav-btn:hover{{border-color:var(--accent);background:#12303a;transform:translateY(-1px)}}
.nav-btn.primary{{background:var(--accent);color:#04121a;border-color:var(--accent)}}
.nav-btn.primary:hover{{filter:brightness(1.08);background:var(--accent)}}
/* report switcher (tabs) — links every configured report; active one highlighted */
.nav-tabs{{display:inline-flex;gap:4px;padding:4px;border:1px solid var(--line);border-radius:11px;
background:var(--bg)}}
.nav-tab{{display:inline-flex;align-items:center;text-decoration:none;font-weight:600;font-size:13px;
padding:7px 14px;border-radius:8px;color:var(--mut);white-space:nowrap;transition:color .12s,background .12s}}
.nav-tab:hover{{color:var(--ink);background:var(--panel)}}
.nav-tab.on{{color:var(--ink);background:var(--panel);box-shadow:inset 0 0 0 1px var(--line)}}
.nav-tab.on::before{{content:"";width:7px;height:7px;border-radius:50%;background:var(--accent);
margin-right:8px}}
.nav-dojo{{display:inline-flex;align-items:center;gap:7px;text-decoration:none;font-weight:600;font-size:13px;
padding:8px 14px;border-radius:9px;border:1px solid var(--line);color:var(--mut);background:transparent;
transition:border-color .12s,color .12s}}
.nav-dojo:hover{{border-color:var(--accent);color:var(--ink)}}
.fresh{{color:var(--mut);font-size:12.5px}}
.nav-btn.refresh{{font-size:12.5px;font-weight:600;padding:7px 13px;color:var(--mut)}}
.nav-btn.refresh .ref-ico{{font-size:15px;line-height:1;display:inline-block}}
.nav-btn.refresh:hover{{color:var(--ink)}}
.nav-btn.refresh.busy{{opacity:.7;pointer-events:none}}
.nav-btn.refresh.busy .ref-ico{{animation:spin .7s linear infinite}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
@media (prefers-reduced-motion:reduce){{.nav-btn.refresh.busy .ref-ico{{animation:none}}}}
/* "Justification" link + modal (show page) */
.just-link{{color:var(--accent);text-decoration:none;font-size:12px;white-space:nowrap}}
.just-link:hover{{text-decoration:underline}}
.modal-backdrop{{position:fixed;inset:0;background:rgba(4,8,14,.72);display:flex;align-items:center;
justify-content:center;z-index:200;padding:20px}}
.modal-backdrop[hidden]{{display:none}}
.modal{{background:var(--panel);border:1px solid var(--line);border-radius:14px;max-width:640px;width:100%;
max-height:80vh;overflow:auto;padding:22px 24px 24px;box-shadow:0 24px 60px rgba(0,0,0,.6)}}
.modal-head{{display:flex;align-items:center;justify-content:space-between;gap:10px}}
.modal-ra{{font-size:11px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;color:var(--accent);
background:#12303a;border:1px solid var(--line);padding:3px 10px;border-radius:20px}}
.modal-x{{background:transparent;border:0;color:var(--mut);font-size:26px;line-height:1;cursor:pointer;padding:0 4px}}
.modal-x:hover{{color:var(--ink)}}
.modal-title{{font-size:16px;font-weight:700;margin:14px 0 12px;color:var(--ink);text-wrap:balance}}
.modal-body{{color:#cdd6e2;font-size:14px;line-height:1.65;margin:0;white-space:pre-wrap}}
.modal-meta{{color:var(--mut);font-size:12.5px;margin-top:16px;border-top:1px solid var(--line);padding-top:12px}}
.modal-meta b{{color:#cfd9e4;font-weight:600}}
.filters{{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;margin:6px 0 18px;padding:14px 16px;
background:var(--panel2);border:1px solid var(--line);border-radius:12px}}
.filters label{{display:flex;flex-direction:column;gap:5px;font-size:10.5px;text-transform:uppercase;
letter-spacing:.05em;color:var(--mut);font-weight:600}}
.filters select,.filters input{{box-sizing:border-box;height:34px;background:var(--panel);color:var(--ink);
border:1px solid var(--line);border-radius:8px;padding:7px 9px;font-size:13px;min-width:150px}}
.filters input{{min-width:200px}}
.filters .btns{{display:flex;gap:8px;align-items:flex-end}}
.filters .btn{{box-sizing:border-box;background:var(--accent);color:#04121a;border:1px solid var(--accent);
border-radius:8px;padding:7px 16px;font-weight:700;font-size:13px;line-height:1;cursor:pointer;
text-decoration:none;display:inline-flex;align-items:center;height:34px}}
.filters .btn.clear{{background:transparent;color:var(--mut);border:1px solid var(--line);font-weight:600}}
.filters .btn.clear:hover{{color:var(--ink);border-color:var(--mut)}}
.pager{{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:16px;flex-wrap:wrap}}
.pager a,.pager .dis{{padding:6px 13px;border:1px solid var(--line);border-radius:8px;text-decoration:none;
font-size:13px;font-weight:600}}
.pager a{{color:var(--accent)}}.pager a:hover{{border-color:var(--accent)}}
.pager .dis{{color:#48566a}}.pager .info{{color:var(--mut);font-size:13px;font-weight:400;border:0;padding:0}}
</style></head><body><div class="wrap">
<header class="rpt"><div class="hdr-left">
<img class="brand-logo" src="%LOGO%" alt="%LOGOALT%" width="46" height="46">
<div><p class="eyebrow">%EYEBROW%</p>
<h1>{title}</h1><p class="sub">{subtitle}</p></div></div>
<div class="hdr-right"><div class="stamp">Live from DefectDojo<br>{gen}</div></div></header>
{body}
<p class="foot">{live}%FOOTER%</p>
</div>
<script>
(function(){{
  var t=document.createElement('div');t.className='tip';document.body.appendChild(t);
  document.addEventListener('mouseover',function(e){{
    var el=e.target.closest?e.target.closest('[data-tip]'):null;
    if(!el){{t.style.opacity='0';return}}
    t.textContent=el.getAttribute('data-tip');
    var r=el.getBoundingClientRect();
    t.style.left=(r.left+r.width/2)+'px';t.style.top=(r.top-10)+'px';t.style.opacity='1';
  }});
  document.addEventListener('mouseout',function(e){{
    if(e.target.closest&&e.target.closest('[data-tip]'))t.style.opacity='0';
  }});
}})();
</script>
</body></html>"""

def page(cfg, *, title, subtitle="", body="", gen="", live="") -> str:
    """Assemble a full HTML page: fill the per-render fields ({title}/{body}/{gen}/…)
    first, then substitute the branding tokens (%LOGO%/%EYEBROW%/%LOGOALT%/%FOOTER%).
    Doing branding AFTER str.format keeps operator-supplied footer/branding text (which
    may contain literal braces) from ever reaching the format parser. Shared by the CLI
    renderer and the live server so both pick up the same `branding:` config."""
    b = _branding(cfg)
    doc = PAGE.format(title=title, subtitle=subtitle, body=body, gen=gen, live=live)
    return (doc.replace("%LOGO%", b["logo"])
               .replace("%EYEBROW%", b["eyebrow"])
               .replace("%LOGOALT%", b["logo_alt"])
               .replace("%FOOTER%", b["footer"]))


def _live_link_html(live_url) -> str:
    """Footer prefix pointing at the always-current served version, when known."""
    if not live_url:
        return ""
    u = esc(live_url.rstrip("/") + "/report")
    return f'Always-current live version: <a href="{u}">{u}</a> · '


# ---------------------------------------------------- publish into the Dojo UI (A + B)
def _find_or_create_product(dojo, name, desc, pt_id):
    p = next((x for x in dojo.paginate("products", name=name, prod_type=pt_id)
              if x["name"] == name), None)
    if p:
        return p["id"]
    r = dojo.post("products/", {"name": name, "description": desc, "prod_type": pt_id})
    if r.status_code not in (200, 201):
        sys.exit(f"Could not create product '{name}': {r.status_code} {r.text[:200]} "
                 "(the API token may lack add_product — create it once in the UI).")
    print(f"  created product '{name}' (#{r.json()['id']})")
    return r.json()["id"]


def _find_or_create_engagement(dojo, name, product_id):
    e = next((x for x in dojo.paginate("engagements", product=product_id, name=name)
              if x["name"] == name), None)
    if e:
        return e["id"]
    today = date.today().isoformat()
    r = dojo.post("engagements/", {"name": name, "product": product_id,
                                   "target_start": today, "target_end": today,
                                   "engagement_type": "CI/CD", "status": "In Progress"})
    if r.status_code not in (200, 201):
        sys.exit(f"Could not create engagement '{name}': {r.status_code} {r.text[:200]}")
    print(f"  created engagement '{name}' (#{r.json()['id']})")
    return r.json()["id"]


def _attach_html(dojo, eng_id, title, html_text):
    """Attach the styled HTML to the engagement's Files. No API delete exists, so we
    use a dated title and skip if that snapshot is already present (idempotent/day)."""
    # GET returns {"engagement_id": N, "files": [{id,title,file}, ...]}, not a bare list.
    existing = dojo.get(f"engagements/{eng_id}/files/")
    files = (existing.json() or {}).get("files", []) if existing.ok else []
    if any((f or {}).get("title") == title for f in files):
        print(f"    file '{title}' already attached — skipping")
        return
    r = requests.post(f"{dojo.base}/api/v2/engagements/{eng_id}/files/",
                      headers=dojo.headers, data={"title": title},
                      files={"file": (title, html_text.encode("utf-8"), "text/html")}, timeout=90)
    if r.status_code in (200, 201):
        print(f"    attached file '{title}'")
    elif "Unsupported extension" in r.text:
        # DefectDojo's FileUpload.clean() validates the extension via Path(self.file.url),
        # which on S3-backed media is a SIGNED URL with a query string — so the parsed
        # suffix is never a bare '.html' and every upload 400s. Not fixable client-side;
        # the full HTML is still available as the CI artifact. See notes in the workflow.
        print(f"    SKIP attach '{title}': DefectDojo S3 file-upload bug (signed-URL "
              "extension check) — full HTML is in the run's artifacts instead.")
    else:
        print(f"    WARN could not attach '{title}': {r.status_code} {r.text[:160]}")


def summary_md(report, findings, cfg, limit=1990, live_url=None):
    """A compact Markdown summary (KPIs + matrices only) for the engagement description,
    which DefectDojo caps at 2000 chars. The full report — repo breakdown, accepted
    register, findings detail — lives in the attached HTML File."""
    scope = {**cfg.get("open_scope", {}), **(report.get("scope") or {})}
    sevs = cfg.get("severities", ["Critical", "High", "Medium", "Low", "Info"])
    open_f = [f for f in findings if _in_scope(f, scope)]
    parts = [f"## {report['title']}", "",
             f"_{report.get('subtitle', '')}_ — generated {date.today().isoformat()}", ""]
    if live_url:
        parts += [_live_link_md(live_url), ""]
    for sec in report.get("sections", []):
        if sec["kind"] == "kpis":
            parts.append(md_kpis(findings, scope, sevs))
        elif sec["kind"] == "matrix":
            parts.append(md_matrix(open_f, sec.get("rows", "environment"), sevs, cfg, sec["title"]))
    parts.append("_Full report — repository breakdown, accepted register, findings detail — "
                 "is attached as HTML in this engagement's **Files** tab._")
    md = "\n".join(parts)
    if len(md) > limit:
        md = md[:limit - 60].rstrip() + "\n\n_…truncated; see the attached HTML for the full report._"
    return md


def publish_to_dojo(dojo, cfg, reports, findings, live_url=None):
    pub = cfg.get("publish") or {}
    pt = next((p for p in dojo.paginate("product_types") if p["name"] == cfg["product_type"]), None)
    if not pt:
        sys.exit(f"Product type '{cfg['product_type']}' not found.")
    prod_id = _find_or_create_product(dojo, pub.get("product", "Security Reports"),
                                      " ".join((pub.get("product_description") or "").split()), pt["id"])
    stamp = date.today().isoformat()
    for r in reports:
        eng_name = r.get("engagement") or r["title"]
        eng_id = _find_or_create_engagement(dojo, eng_name, prod_id)
        print(f"  {r['name']} -> product '{pub.get('product')}' / engagement '{eng_name}' (#{eng_id})")
        # A) compact Markdown summary as the engagement description (renders inline in
        #    the Dojo UI; the field is capped at 2000 chars so this is KPIs + matrices).
        pr = dojo.patch(f"engagements/{eng_id}/", {"description": summary_md(r, findings, cfg, live_url=live_url)})
        print("    description updated" if pr.status_code in (200, 201)
              else f"    WARN description PATCH: {pr.status_code} {pr.text[:160]}")
        # B) styled HTML as a downloadable dated snapshot in the engagement's Files
        _attach_html(dojo, eng_id, f"{r['name']}-{stamp}.html", render_report(r, findings, cfg, live_url))


def main():
    ap = argparse.ArgumentParser(description="Render config/reports.yaml against DefectDojo.")
    ap.add_argument("--report", help="render only this report name (default: all)")
    ap.add_argument("--config", help="path to reports.yaml (default: $DOJO_DASH_CONFIG "
                                     "or ./config/reports.yaml)")
    ap.add_argument("--url")
    ap.add_argument("--token")
    ap.add_argument("--findings-json", help="render from a normalized findings dump instead of the API")
    ap.add_argument("--out-dir", default=str(OUT_DIR))
    ap.add_argument("--format", choices=["html", "md", "both"], default="html",
                    help="html (styled page), md (GitHub-flavored, for the Actions job summary), or both")
    ap.add_argument("--open", action="store_true", help="open the rendered report(s) in a browser")
    ap.add_argument("--publish-to-dojo", action="store_true",
                    help="also publish each report INTO the DefectDojo UI (dedicated Reports "
                         "product: Markdown -> engagement description, HTML -> attached File)")
    ap.add_argument("--live-url", default=os.environ.get("REPORT_LIVE_URL"),
                    help="Base URL of the live report host; adds a link to <url>/report in "
                         "every rendered report. Defaults to $REPORT_LIVE_URL, else the "
                         "DefectDojo base URL (the live page shares its host).")
    args = ap.parse_args()

    cfg = load_config(args.config)
    dojo = None
    if args.findings_json:
        findings = json.loads(pathlib.Path(args.findings_json).read_text())
        print(f"Loaded {len(findings)} findings from {args.findings_json}")
    else:
        from dojo_api import Dojo
        dojo = Dojo(args.url, args.token)
        print(f"DefectDojo : {dojo.base}")
        findings = _normalize_api(dojo, cfg["product_type"])
        print(f"Fetched {len(findings)} findings for product type '{cfg['product_type']}'")

    reports = cfg.get("reports", [])
    if args.report:
        reports = [r for r in reports if r["name"] == args.report]
        if not reports:
            sys.exit(f"No report named '{args.report}' in config/reports.yaml")

    # Where the always-current served copy lives: explicit --live-url/$REPORT_LIVE_URL,
    # else the DefectDojo host itself (the /report page shares the ALB + host).
    live_url = args.live_url or (dojo.base if dojo is not None else args.url)

    if args.publish_to_dojo:
        if dojo is None:
            from dojo_api import Dojo
            dojo = Dojo(args.url, args.token)
            live_url = live_url or dojo.base
        print(f"Publishing {len(reports)} report(s) into DefectDojo ({dojo.base}):")
        publish_to_dojo(dojo, cfg, reports, findings, live_url=live_url)

    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for r in reports:
        if args.format in ("html", "both"):
            path = out_dir / f"{r['name']}.html"
            path.write_text(render_report(r, findings, cfg, live_url), encoding="utf-8")
            print(f"  wrote {path}")
            if args.open:
                webbrowser.open(path.resolve().as_uri())
        if args.format in ("md", "both"):
            mpath = out_dir / f"{r['name']}.md"
            mpath.write_text(render_report_md(r, findings, cfg, live_url), encoding="utf-8")
            print(f"  wrote {mpath}")


if __name__ == "__main__":
    main()

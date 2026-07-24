# Configuration

Everything dojo-dash renders is declared in one YAML file (`config/reports.yaml` by
default). No code changes are needed to adopt it — set your product type, list your repos,
brand it, and define the control map.

**File locations** (all env-overridable):

| Env var | Default | Purpose |
|---|---|---|
| `DOJO_DASH_CONFIG` | `/app/config/reports.yaml` (image) or `./config/reports.yaml` | The main config (required). |
| `DOJO_DASH_SLA` | `dojo_sla.yaml` next to the config | SLA windows for the evidence report (optional). |
| `DOJO_DASH_SUPPRESSIONS` | `suppressions.yaml` next to the config | Risk-acceptance justifications (optional). |
| `DOJO_DASH_OUT` | `./output/reports` | Where `dojo-dash render` writes HTML/Markdown. |

The two optional files degrade gracefully — with neither present, reports still render;
the SLA section shows "not configured" and accepted findings just lack justification text.

## Top-level keys

```yaml
product_type: "My Platform"     # REQUIRED — the DefectDojo product type to report on
severities: [Critical, High, Medium, Low]   # order drives columns + colors (Info is dropped from the pull)
```

### `branding`

All optional; sensible generic defaults apply (a built-in shield logo, the "Security"
eyebrow, a neutral footer).

```yaml
branding:
  eyebrow: "My Platform · Security"   # small uppercase label above the title
  logo: "./assets/my-logo.svg"        # file path (rel. to this config), data: URI, or http(s) URL
  logo_alt: "My Platform"
  home_url: "/"                       # where the "Return to DefectDojo" button points
  home_label: "Return to DefectDojo"
  footer: "Rendered by dojo-dash."    # footer text (may contain simple HTML)
```

A file-path logo is read and base64-inlined at render time, so the HTML stays
self-contained. SVG, PNG, JPG, GIF and WebP are supported.

### `github`

Adds a "GitHub" deep-link pill next to any product whose name is in `repos`.

```yaml
github:
  org: my-org
  repos: [web, api, infra]
```

### `open_scope`

Which DefectDojo finding flags define an "open" finding (the default scope for every
report). Maps directly to the API's booleans.

```yaml
open_scope: { active: true, duplicate: false, risk_accepted: false, false_p: false, out_of_scope: false }
```

### `alerts`

Email alerts on **newly-appeared** findings. The live server (`dojo-dash serve`) already
re-pulls every finding on a fixed cadence to keep the dashboard warm; that same poll is
used as an always-on detector. When a finding at an alert severity appears that wasn't
present before, one batched email is sent. Fully **opt-in**: nothing happens unless
recipients **and** an SMTP URL are configured. Every value is overridable by an environment
variable — resolution is **env var > this yaml > default** — and secrets stay env-only.

```yaml
alerts:
  enabled: true                    # master switch
  severities: [Critical, High]     # which severities alert          (ALERT_SEVERITIES)
  recipients: ["secops@example.com"] # or set ALERT_EMAILS
  subject_prefix: "[dojo-dash] "   #                                 (ALERT_SUBJECT_PREFIX)
  link_base: "https://dojo.example.com"  # deep-link findings        (ALERT_LINK_BASE)
  min_interval_seconds: 0          # min seconds between emails       (ALERT_MIN_INTERVAL_SECONDS)
  quiet_hours:                     # only email inside a local-time window; hold otherwise
    tz: America/Los_Angeles        # any IANA zone; "" disables       (ALERT_HOURS_TZ)
    start: 8                       # inclusive local hour (24h)       (ALERT_HOURS_START)
    end: 20                        # exclusive local hour             (ALERT_HOURS_END)
    gate_all: true                 # false => Critical pages 24/7     (ALERT_HOURS_GATE_ALL)
  dedup:                           # remembers which findings were already emailed
    backend: memory                # memory | file | mongodb          (ALERT_DEDUP_BACKEND)
    mongo:                         # when backend: mongodb (needs the `mongodb` extra)
      uri: mongodb://localhost:27017          #                       (ALERT_DEDUP_MONGO_URI)
      database: dojo_dash
      collection: alerted_findings
    file:
      path: /app/state/alert-dedup.json       # put it on a volume    (ALERT_STATE_FILE)
```

**SMTP** is env-only (it carries a password): set `ALERT_SMTP_URL` (falls back to
`DD_EMAIL_URL`), e.g. `submission://user:pass@smtp.example.com:587`. Schemes: `smtp`
(25), `smtps`/`smtp+ssl` (465, implicit TLS), `smtp+tls`/`submission` (587, STARTTLS).

**Never spams the backlog.** On its first poll against an *empty* dedup store it
baseline-seeds every currently-open finding as already-seen and stays silent — only
findings appearing in later polls alert.

**Quiet hours** hold (never drop) off-window findings and flush them when the window next
opens. With `gate_all: false`, Critical findings bypass the window and email 24/7 while
High still waits.

**Dedup backends** control whether "already emailed" survives a restart:
- `memory` (default) — in-process only; a restart re-baselines (never double-sends, but a
  finding that first appeared during downtime won't alert).
- `file` — an atomic JSON file at `path`; durable only if the path is on a persistent
  volume.
- `mongodb` — a `{_id: finding_id}` collection; install the extra (`pip install
  dojo-dash[mongodb]`) and point a lightweight Mongo at it. Durable across restarts; if
  Mongo is unreachable at boot it logs and falls back to `memory` for that run.

A finding id is written to the store **only after its email successfully sends**, so a send
failure retries and nothing is ever emailed twice.

### Environments — `environment_labels` / `environment_order`

DefectDojo tags each test with an environment. Relabel the raw names into human terms and
set their display order.

```yaml
environment_labels:
  manual: "Source (static)"
  Development: "Dev"
  Production: "Prod"
environment_order: [manual, Development, Staging, Production]
```

### Scan-type buckets — `scan_types` / `scan_detail`

Map each DefectDojo **engagement** name to a coarse discipline (Static / DAST / Runtime)
and a finer scanner. Anything unlisted falls through to the default.

```yaml
scan_types:
  DAST: ["DAST"]
  Runtime: ["CSPM", "KSPM", "Container Images"]
scan_type_default: "Static"
scan_type_order: ["Static", "DAST", "Runtime"]

scan_detail:                          # splits Runtime into individual scanners for the filter
  DAST: ["DAST"]
  "AWS (CSPM)": ["CSPM"]
  "EKS (KSPM)": ["KSPM"]
  "Container images": ["Container Images"]
scan_detail_default: "Static"
scan_detail_order: ["Static", "DAST", "AWS (CSPM)", "EKS (KSPM)", "Container images"]
```

### `control_map` / `control_map_label`

Drives the evidence report's control→evidence table. Fully declarative, so it works for
SOC 2, ISO 27001, CASA, or any framework. `control` and `evidence` may contain simple HTML
and these live `{placeholders}`: `total`, `accepted`, `mitigated`, `open_ch`,
`engagements`, `products`, `environments`.

```yaml
control_map_label: "TSC"              # header for the first column
control_map:
  - tsc: "CC7.1"
    control: "Findings are remediated within per-severity SLAs."
    evidence: "SLA table above; {open_ch} open Critical/High right now."
```

### `reports`

A list of reports; each becomes a page (`/report/<name>`) and, for the CLI, an
`<name>.html`. The first report is the dashboard home.

```yaml
reports:
  - name: posture
    title: "Security Posture"
    nav_label: "Posture"              # short label for the report switcher
    subtitle: "…"
    engagement: "Posture"             # engagement name when publishing into the Dojo UI
    sections:
      - kind: kpis
        title: "At a glance"
        desc: "…"
```

**Section kinds:**

| `kind` | Renders |
|---|---|
| `kpis` | Headline count cards (Open, per-severity, Accepted, Mitigated). |
| `disposition` | Disposition × severity table. Optional `rows: [Open, Accepted, Mitigated]`. |
| `matrix` | Severity heatmap. `rows:` one of `scan_type`, `environment`, `product`. |
| `repo-summary` | Per-repository open / accepted / mitigated. |
| `findings` | Grouped open-findings summary that deep-links into the browser. `group_by:` a dimension. |
| `accepted` | The risk-acceptance register (per-repo accepted counts). |
| `sla-compliance` | Open vs SLA window per severity (needs `dojo_sla.yaml`). |
| `scan-coverage` | Scanning activity by engagement (repos × environments × findings). |
| `control-map` | The `control_map` table. |

Every section takes an optional `title` and `desc`.

### `publish`

Where `dojo-dash render --publish-to-dojo` writes reports back into the DefectDojo UI (a
dedicated product, one engagement per report).

```yaml
publish:
  product: "Security Reports"
  product_description: "…"
```

## Optional files

**`dojo_sla.yaml`** — per-severity SLA windows (days) for the evidence report:

```yaml
windows: { critical: 7, high: 30, medium: 90, low: 180 }
enforce: { critical: true, high: true, medium: true, low: false }
```

**`suppressions.yaml`** — a register of documented risk acceptances. When a finding is
risk-accepted in DefectDojo *and* matches an entry, its justification / owner / re-review
trigger show in a popover on the findings page:

```yaml
suppressions:
  - id: RA-1
    kind: accepted-risk
    owner: "Platform team"
    justification: "Why this risk is accepted."
    re_review_trigger: "Next base-image bump."
    match:
      rules: ["CVE-2022-40897"]   # substring-matched against the finding text
      paths: ["usr/lib/**"]       # fnmatch against the finding's file_path
```

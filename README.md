# dojo-dash

A config-as-code reporting dashboard for [DefectDojo](https://www.defectdojo.org/) — the
severity heatmaps, disposition breakdowns, a filterable findings browser, and a **SOC 2 /
CASA evidence report** that the built-in dashboard doesn't give you. It reads the
DefectDojo REST API live and renders self-contained HTML: no database, no build step, no
external assets.

Everything you see is driven by one YAML file. Point it at your product type, list your
repos, drop in your logo, and you're done.

```
┌───────────────┐   reads REST API    ┌───────────────┐   HTML over HTTP   ┌─────────┐
│  DefectDojo   │◀────────────────────│   dojo-dash   │───────────────────▶│ browser │
│  (your data)  │   every 5 minutes   │  (this tool)  │  self-contained    │         │
└───────────────┘                     └───────────────┘                    └─────────┘
```

- **Two reports out of the box** — a *posture* dashboard (KPIs, disposition ×
  severity, scan-type / environment / repository heatmaps, an open-findings detail) and a
  focused *SOC 2 / CASA evidence* report (SLA compliance, detection coverage, the risk-
  acceptance register, and a config-driven control→evidence map).
- **Filterable findings browser** — every table deep-links into a paginated, sortable,
  server-side-filtered list; each row links back into its DefectDojo finding.
- **Immediate Critical/High email alerts** — the same 5-minute poll that keeps the
  dashboard warm also emails you the moment a new Critical/High finding appears, once
  ever per finding. Opt-in; see [docs/alerting.md](docs/alerting.md).
- **Config-as-code** — repos, environments, scan-type buckets, branding, and the control
  map are all declarative. No code changes to adopt it.
- **Tiny & self-contained** — Python stdlib + `requests` + `pyyaml`, one ~80 MB image.

## Quickstart — see it in 2 minutes

Requires Docker. This brings up PostgreSQL, a minimal DefectDojo (on `:8080`), and
dojo-dash (on `:8091`):

```bash
git clone https://github.com/nuday-ai/dojo-dash && cd dojo-dash
cp .env.example .env
docker compose up -d            # wait ~1–2 min for DefectDojo to initialise
docker compose run --rm seed    # load sample findings so the dashboard isn't empty
open http://localhost:8091/report
```

- Dashboard: **http://localhost:8091/report** — the SOC 2 evidence view is one click away
  in the report switcher (or at `/report/evidence`).
- DefectDojo UI: **http://localhost:8080** (`admin` / the password in your `.env`).

Tear down with `docker compose down -v`.

> The demo stack runs DefectDojo unauthenticated on localhost for convenience. In
> production you front **both** DefectDojo and dojo-dash with your own auth proxy — see
> [docs/deployment.md](docs/deployment.md).

## Point it at your DefectDojo

Run just the published image against an existing DefectDojo and mount your config:

```bash
docker run --rm -p 8091:8091 \
  -e DD_URL=https://defectdojo.example.com \
  -e DD_API_TOKEN=•••• \
  -v "$PWD/config:/app/config:ro" \
  ghcr.io/nuday-ai/dojo-dash:latest
```

Then edit `config/reports.yaml`:

```yaml
product_type: "My Platform"        # the DefectDojo product type your findings live under
branding:
  eyebrow: "My Platform · Security"
  logo: "./assets/my-logo.svg"     # a path, data: URI, or omit for the built-in mark
github:
  org: my-org
  repos: [web, api, infra]         # products that get a "GitHub" deep-link pill
```

Auth is either `DD_API_TOKEN` or `DD_ADMIN_USER` / `DD_ADMIN_PASSWORD` (exchanged for a
token). Nothing is logged. Full reference: [docs/configuration.md](docs/configuration.md).

## Render static HTML (no server)

Prefer a one-off artifact — a report attached to a ticket, published as a CI job summary,
or committed as evidence?

```bash
pip install dojo-dash
dojo-dash render --report posture --open          # against DD_URL
dojo-dash render --findings-json dump.json        # fully offline, from an export
```

`--findings-json` renders from a dump with no API access at all — handy for CI and demos.
See `fixtures/findings.json` for the shape.

## The two reports

| Report | Path | For |
|---|---|---|
| **Posture** | `/report` | Day-to-day: what's open, where, and how bad. |
| **SOC 2 / CASA Evidence** | `/report/evidence` | Auditors: SLA remediation cadence, detection coverage, the documented risk-acceptance register, and each control mapped to its live evidence. |

Both are just entries in `reports.yaml` — add, remove, or reorder their sections, or
define your own report, without touching code.

## How it fits a deployment

The published GHCR image is generic; your specifics live in the mounted config. That means
you can bake dojo-dash into infrastructure and pull the latest image at deploy time while
keeping your repo list, product names, and branding in your own (private) config. See
[docs/deployment.md](docs/deployment.md) for reverse-proxy/auth patterns and an
infrastructure example.

## Development

```bash
pip install -e .
dojo-dash render --findings-json fixtures/findings.json --out-dir out   # offline smoke test
python -m py_compile dojo_dash/*.py
```

## Releasing

The version lives in **one place**: `__version__` in `dojo_dash/__init__.py`. It drives the
pip package version, the server's User-Agent, and the published image tags.

1. Bump `__version__` (e.g. `0.1.0` → `0.1.1`) and merge to `main`.
2. Release the current version one of two ways:
   - **Manual dispatch** — Actions → **release** → *Run workflow*. It creates the
     `v<version>` git tag and GitHub Release for you.
   - **Tag push** — `git tag v0.1.1 && git push origin v0.1.1` (the tag must equal
     `__version__`, or the run fails).

The `release` workflow builds the multi-arch image and pushes
`ghcr.io/nuday-ai/dojo-dash:{v<version>, <version>, latest, sha-<sha>}`. It **fails if that
version is already published to GHCR**, so every release has to bump `__version__` first —
you can't silently overwrite a released tag. Deployments that pin `v<version>` get an
immutable image; `latest` always points at the newest release.

## License

Apache-2.0. dojo-dash talks to DefectDojo purely over its public REST API and bundles none
of its code.

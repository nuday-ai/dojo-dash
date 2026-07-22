# Deployment

dojo-dash is a single container that serves HTML on port `8091`. It has **no
authentication of its own** — it assumes the same trust boundary as your DefectDojo UI.
Run it behind a reverse proxy that handles auth, exactly as you'd front DefectDojo.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `DD_URL` | `http://localhost:8080` | DefectDojo API base. |
| `DD_API_TOKEN` | — | Preferred auth. |
| `DD_ADMIN_USER` / `DD_ADMIN_PASSWORD` | `admin` / — | Alternative auth (exchanged for a token). |
| `DOJO_DASH_CONFIG` | `/app/config/reports.yaml` | Mount your config here. |
| `REPORT_PORT` | `8091` | Listen port. |
| `REPORT_REFRESH_INTERVAL` | `300` | Poll + page auto-reload cadence (seconds). |
| `REPORT_PAGE_SIZE` | `1000` | DefectDojo API page size per pull. |
| `ALERT_*` | — | Critical/High email alerts — see [alerting.md](alerting.md). |

Secrets (`DD_API_TOKEN`, admin password, SMTP creds) are never logged. Inject them from
your secrets manager, not into the image.

## Auth: put a proxy in front

The container serves everything under `/report/*` (plus `/health` for probes). Route those
paths through your proxy's auth. Two common patterns:

**oauth2-proxy / nginx** — terminate auth at the proxy, then `proxy_pass` `/report/` to
`dojo-dash:8091`. Point `branding.home_url` at your DefectDojo UI so "Return to DefectDojo"
lands the user back in an authenticated session.

**AWS ALB + Cognito** — an `authenticate-cognito` action on the `/report/*` listener rule,
forwarding to a target group on `8091`. Use the **same** user pool/client as the DefectDojo
UI so a logged-in user isn't re-prompted. Health-check the target group against
`/report/health` (it returns `200` without touching DefectDojo, so the target is healthy as
soon as the process starts — even before DefectDojo finishes booting).

Because the served pages use root-relative links (`/finding/42`, `/product/7`, `/`), they
resolve straight into DefectDojo under the same session when both sit behind one proxy.

## Consuming the published image from infrastructure

The GHCR image is **generic**; your specifics (product type, repo list, branding, control
map) live in the config you mount. This lets you keep the image at a pinned tag in your IaC
and keep your config private:

```yaml
# docker-compose / ECS / k8s — the shape is the same
image: ghcr.io/nuday-ai/dojo-dash:v0.1.0     # pin a tag; bump to upgrade
environment:
  DD_URL: http://defectdojo-internal:8080
  DD_API_TOKEN: ${DD_API_TOKEN}
volumes:
  - ./my-config:/app/config:ro               # your reports.yaml (+ optional sla/suppressions)
```

Deploy flow: your IaC ships **only the config** (a small bundle) and references the pinned
image tag; the host pulls the public image at boot. Bumping the tag (or the config) is your
upgrade signal. This keeps a single source of truth — the image — while your repo list and
branding never leave your private config.

## Sizing & operations

- **Stateless.** All state is the in-memory finding cache, rebuilt on each poll. Restarts
  and horizontal scaling are safe. (The optional alert dedup state is the one thing worth
  persisting — see [alerting.md](alerting.md).)
- **One pull per interval**, shared by every request and report, so load on DefectDojo is
  flat regardless of dashboard traffic.
- **Health/readiness:** `/report/health` → `200 ok`, DB-independent.

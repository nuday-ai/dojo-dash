# Critical/High new-finding email alerts

dojo-dash already re-pulls the whole finding set every few minutes to keep the dashboard
warm. That same poll doubles as an always-on detector: when a **new Critical/High finding**
appears, it emails you — at import time, not when an SLA clock is about to breach.

It's **opt-in**: nothing is sent unless you configure recipients and an SMTP URL.

## What it guarantees

- **No backlog spam.** On the first successful poll after startup, every currently-open
  Critical/High finding is recorded as "already seen" and *no email is sent*. Only findings
  that appear in *later* polls can alert. So enabling it on an instance with 200 open highs
  sends zero emails — until the 201st arrives.
- **Once ever per finding.** A finding is emailed at most once. Ids are remembered in
  memory, and optionally in a state file so a container restart doesn't re-alert.
- **Batched & rate-limited.** New findings from a poll are collected into a single email,
  and at most one email is sent per `ALERT_MIN_INTERVAL_SECONDS`.
- **Fails safe.** If the send fails, the findings stay queued and are retried on the next
  poll — they're never marked "seen" until an email actually goes out.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ALERT_EMAILS` | — | Comma/space-separated recipients. **Empty ⇒ alerting off.** |
| `ALERT_SMTP_URL` | `DD_EMAIL_URL` | `smtp[+tls\|+ssl]://user:pass@host:port`. Falls back to a DefectDojo stack's own `DD_EMAIL_URL`. |
| `ALERT_FROM` | `DD_EMAIL_FROM`, else SMTP user | From address. |
| `ALERT_SEVERITIES` | `Critical,High` | Which severities alert. |
| `ALERT_MIN_INTERVAL_SECONDS` | `0` | Minimum seconds between emails (0 ⇒ at most once per poll). |
| `ALERT_STATE_FILE` | — | Path to persist seen-ids across restarts (see below). |
| `ALERT_LINK_BASE` | — | Base URL for finding deep-links, e.g. `https://defectdojo.example.com`. |
| `ALERT_SUBJECT_PREFIX` | `[dojo-dash] ` | Subject line prefix. |

The SMTP scheme selects transport: `smtp` (plain), `smtp+tls` / `smtp+starttls` /
`submission` (STARTTLS, usually port 587), `smtps` / `smtp+ssl` (implicit TLS, usually
465). The `submission` scheme is accepted because that's what DefectDojo's `DD_EMAIL_URL`
often uses — so `ALERT_SMTP_URL` can fall back to it directly. Credentials in the URL are
used to `LOGIN`; the password is never logged.

Example:

```bash
ALERT_EMAILS="secops@example.com, oncall@example.com"
ALERT_SMTP_URL="smtp+tls://apikey:••••@smtp.example.com:587"
ALERT_FROM="dojo-dash@example.com"
ALERT_LINK_BASE="https://defectdojo.example.com"
```

## Persisting dedup state across restarts

Without a state file, the boot **baseline seed** already prevents re-alerting: on restart,
every finding that exists (including ones alerted just before the restart) is in the fresh
baseline, so it won't re-fire. This is the right default for most deployments.

Set `ALERT_STATE_FILE=/data/alert-state.json` (on a persistent volume) when you'd rather
the instance keep an explicit memory — for example so that findings created *during*
downtime are alerted on the next start instead of being absorbed into the baseline.

## Interaction with DefectDojo's own notifications

This is complementary to DefectDojo's built-in `sla_breach` / `scan_added` notifications,
not a replacement. If you already run a scan-time notifier (e.g. a CI post-import step) and
enable dojo-dash alerts too, both may fire for the same finding — pick one path to avoid
duplicate emails.

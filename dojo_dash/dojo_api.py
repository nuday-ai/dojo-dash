"""Minimal DefectDojo REST API client.

Auth resolution (first that works wins):
  1. DD_API_TOKEN + DD_URL from the environment (CI / a service token).
  2. DD_ADMIN_USER / DD_ADMIN_PASSWORD from the environment, exchanged for an API
     token via /api/v2/api-token-auth/ (used by the report server, which talks to
     DefectDojo over the internal network).
  3. The same keys from an optional env file at $DOJO_DASH_ENV (local convenience).

Nothing here is logged — neither the password nor the resolved token.
"""
from __future__ import annotations

import os
import pathlib
import sys

import requests

# Optional local env file (KEY=VALUE lines). Off by default; set DOJO_DASH_ENV to a
# path to use it. Handy for `dojo-dash render` against a local DefectDojo.
_ENV_FILE = os.environ.get("DOJO_DASH_ENV", "")


def _load_env(path: str) -> dict:
    env: dict = {}
    if not path:
        return env
    p = pathlib.Path(path)
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


class Dojo:
    def __init__(self, url: str | None = None, token: str | None = None):
        env = _load_env(_ENV_FILE)
        self.base = (
            url or os.environ.get("DD_URL") or env.get("DD_URL") or "http://localhost:8080"
        ).rstrip("/")
        token = token or os.environ.get("DD_API_TOKEN") or env.get("DD_API_TOKEN")
        if not token:
            user = os.environ.get("DD_ADMIN_USER") or env.get("DD_ADMIN_USER", "admin")
            pw = os.environ.get("DD_ADMIN_PASSWORD") or env.get("DD_ADMIN_PASSWORD")
            if not pw:
                sys.exit("No DD_API_TOKEN and no DD_ADMIN_PASSWORD (set one, or $DOJO_DASH_ENV).")
            r = requests.post(f"{self.base}/api/v2/api-token-auth/",
                              data={"username": user, "password": pw}, timeout=30)
            r.raise_for_status()
            token = r.json()["token"]
        self.headers = {"Authorization": f"Token {token}"}

    def get(self, path: str, **params) -> requests.Response:
        return requests.get(f"{self.base}/api/v2/{path}", headers=self.headers, params=params, timeout=60)

    def post(self, path: str, payload: dict) -> requests.Response:
        return requests.post(f"{self.base}/api/v2/{path}", headers=self.headers, json=payload, timeout=60)

    def patch(self, path: str, payload: dict) -> requests.Response:
        return requests.patch(f"{self.base}/api/v2/{path}", headers=self.headers, json=payload, timeout=60)

    def paginate(self, path: str, **params):
        """Yield every result across pages."""
        params.setdefault("limit", 100)
        url = f"{self.base}/api/v2/{path}"
        while url:
            r = requests.get(url, headers=self.headers, params=params, timeout=60)
            r.raise_for_status()
            data = r.json()
            yield from data.get("results", [])
            url = data.get("next")
            params = {}  # `next` already encodes them

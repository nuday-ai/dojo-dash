"""Populate a fresh DefectDojo with a handful of sample findings, so the demo
dashboard has something to show. Idempotent-ish: it reuses a product type / product /
engagement of the same name if present, and skips findings whose title already exists
under a test.

    dojo-dash seed                         # against $DD_URL with admin creds
    dojo-dash seed --product-type "Demo Platform"

This is for demos and local testing only — it creates data, so never point it at a real
DefectDojo instance.
"""
from __future__ import annotations

import argparse
import datetime
import sys

_NUM = {"Critical": "S0", "High": "S1", "Medium": "S2", "Low": "S3"}

# (product, engagement, environment, [ (title, severity, disposition), ... ])
# disposition: "open" | "accepted" | "mitigated" | "fp". Engagement names line up with
# the sample reports.yaml scan_detail map (DAST / CSPM / KSPM / Container Images / else Static).
_SEED = [
    ("web-app", "CI", "Development", [
        ("SQL injection in search handler", "High", "open"),
        ("Reflected XSS in error page", "Medium", "open"),
        ("Session cookie missing Secure flag", "Low", "open"),
        ("Verbose stack trace in 500 response", "Low", "mitigated"),
    ]),
    ("web-app", "DAST", "Development", [
        ("Reflected XSS (dynamic crawl)", "High", "open"),
        ("Missing Content-Security-Policy header", "Medium", "open"),
    ]),
    ("api-service", "CI", "Development", [
        ("Hardcoded API token in source", "Critical", "mitigated"),
        ("Vulnerable dependency: lodash < 4.17.21", "Medium", "open"),
        ("Weak password hashing (MD5)", "High", "open"),
    ]),
    ("api-service", "Container Images", "Production", [
        ("CVE-2023-4911 glibc buffer overflow (base image)", "High", "open"),
        ("CVE-2022-40897 setuptools ReDoS", "Medium", "accepted"),
        ("Outdated OpenSSL in image layer", "Medium", "open"),
    ]),
    ("infra", "CSPM", "Production", [
        ("S3 bucket is publicly accessible", "High", "accepted"),
        ("Security group allows 0.0.0.0/0 on 22", "Medium", "open"),
        ("CloudTrail not enabled in all regions", "Medium", "mitigated"),
    ]),
    ("infra", "KSPM", "Production", [
        ("Privileged container in Deployment/api", "High", "open"),
        ("Container runs as root (Deployment/web)", "Medium", "open"),
        ("Secret mounted as environment variable", "Low", "open"),
    ]),
]


def _ok(r):
    return r.status_code in (200, 201)


def _get_or_create(dojo, coll, name, payload):
    for x in dojo.paginate(coll, name=name):
        if x.get("name") == name:
            return x["id"]
    r = dojo.post(f"{coll}/", payload)
    if not _ok(r):
        sys.exit(f"could not create {coll} '{name}': {r.status_code} {r.text[:200]}")
    return r.json()["id"]


def _env_id(dojo, name, cache):
    if name in cache:
        return cache[name]
    for e in dojo.paginate("development_environments"):
        cache[e["name"]] = e["id"]
    if name not in cache:
        r = dojo.post("development_environments/", {"name": name})
        if not _ok(r):
            sys.exit(f"could not create environment '{name}': {r.status_code} {r.text[:160]}")
        cache[name] = r.json()["id"]
    return cache[name]


def _test_type_id(dojo):
    for t in dojo.paginate("test_types"):  # any test type works for the demo
        return t["id"]
    r = dojo.post("test_types/", {"name": "dojo-dash demo"})
    if not _ok(r):
        sys.exit(f"could not resolve a test type: {r.status_code} {r.text[:160]}")
    return r.json()["id"]


def _existing_titles(dojo, test_id):
    return {f.get("title") for f in dojo.paginate("findings", test=test_id)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Seed a demo DefectDojo with sample findings.")
    ap.add_argument("--url", help="DefectDojo base URL (default $DD_URL)")
    ap.add_argument("--token", help="API token (default: admin creds from env)")
    ap.add_argument("--product-type", default="Demo Platform",
                    help="product type to create findings under (match reports.yaml)")
    args = ap.parse_args(argv)

    from .dojo_api import Dojo
    dojo = Dojo(args.url, args.token)
    print(f"Seeding {dojo.base} under product type '{args.product_type}'")

    pt_id = _get_or_create(dojo, "product_types", args.product_type,
                           {"name": args.product_type, "description": "dojo-dash demo data"})
    tt_id = _test_type_id(dojo)
    today = datetime.date.today()
    env_cache: dict = {}
    created = 0

    for product, engagement, env, findings in _SEED:
        prod_id = _get_or_create(dojo, "products", product,
                                 {"name": product, "description": f"Demo product {product}",
                                  "prod_type": pt_id})
        eng_id = _get_or_create(dojo, "engagements", engagement, {
            "name": engagement, "product": prod_id,
            "target_start": today.isoformat(), "target_end": today.isoformat(),
            "engagement_type": "CI/CD", "status": "In Progress"})
        env_id = _env_id(dojo, env, env_cache)
        tr = dojo.post("tests/", {"engagement": eng_id, "test_type": tt_id,
                                  "environment": env_id,
                                  "target_start": today.isoformat(),
                                  "target_end": today.isoformat()})
        if not _ok(tr):
            print(f"  WARN could not create test for {product}/{engagement}: "
                  f"{tr.status_code} {tr.text[:160]}")
            continue
        test_id = tr.json()["id"]
        have = _existing_titles(dojo, test_id)

        for i, (title, sev, disp) in enumerate(findings):
            if title in have:
                continue
            found = today - datetime.timedelta(days=(i * 9 + 3))  # spread discovery dates
            payload = {
                "title": title, "severity": sev, "numerical_severity": _NUM[sev],
                "description": f"Sample {sev} finding for the dojo-dash demo.",
                "test": test_id, "date": found.isoformat(),
                "active": disp == "open", "verified": True,
                "risk_accepted": disp == "accepted",
                "is_mitigated": disp == "mitigated",
                "false_p": disp == "fp",
            }
            if disp == "mitigated":
                payload["mitigated"] = datetime.datetime.combine(
                    found + datetime.timedelta(days=2), datetime.time()).isoformat()
            r = dojo.post("findings/", payload)
            if _ok(r):
                created += 1
            else:
                print(f"  WARN finding '{title}': {r.status_code} {r.text[:160]}")
        print(f"  {product} / {engagement} ({env}) — {len(findings)} findings")

    print(f"Done. Created {created} new finding(s). Open the dashboard to see them.")


if __name__ == "__main__":
    main()

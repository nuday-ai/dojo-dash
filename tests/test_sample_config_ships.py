"""The sample config must exist, parse, and stay generic.

`config/` is not deployment configuration — it is the SAMPLE that ships in the
image so `docker run dojo-dash` works standalone, which the Dockerfile states
in as many words ("Bake the sample config so the image runs standalone. Mount
your own over /app/config"). Deployers override it with a volume mount or
$DOJO_DASH_CONFIG.

It was deleted once (commit 97399cf) as though it were private config. Nothing
caught it at review time; CI failed later and in two separate places — first the
offline render smoke test, then `COPY config /app/config` in the Docker build,
which fails with an opaque "failed to compute cache key: /config: not found".
These tests fail immediately and say why instead.
"""
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"

# Names of the organisation this tool was extracted from. The sample must never
# carry them: the CI smoke test asserts the rendered report has no private
# identifiers, and the image is public.
PRIVATE = ("nuday", "ntur", "agent-vault")


class SampleConfigShips(unittest.TestCase):
    def test_the_directory_the_dockerfile_copies_exists(self):
        self.assertTrue(
            CONFIG.is_dir(),
            "config/ is missing. `COPY config /app/config` in the Dockerfile "
            "fails without it, and the CI render smoke test has no config to "
            "load. It is the SAMPLE config, not private deployment config — "
            "deployers mount over /app/config.")

    def test_reports_yaml_exists_and_parses(self):
        f = CONFIG / "reports.yaml"
        self.assertTrue(f.is_file(), "config/reports.yaml is missing")
        cfg = yaml.safe_load(f.read_text())
        self.assertIn("reports", cfg, "sample config declares no reports")
        names = {r.get("name") for r in cfg["reports"]}
        # The CI smoke test renders both and greps their output by name.
        self.assertLessEqual(
            {"posture", "evidence"}, names,
            f"the smoke test renders posture+evidence; sample has {sorted(names)}")

    def test_the_optional_siblings_parse_when_present(self):
        for name in ("dojo_sla.yaml", "suppressions.yaml"):
            f = CONFIG / name
            if f.is_file():
                yaml.safe_load(f.read_text())   # raises if malformed

    def test_the_sample_carries_no_private_identifiers(self):
        offenders = []
        for f in CONFIG.rglob("*.y*ml"):
            text = f.read_text(errors="ignore").lower()
            offenders += [f"{f.name}: {p}" for p in PRIVATE if p in text]
        self.assertEqual(
            offenders, [],
            f"private identifiers in the SAMPLE config (it ships in a public "
            f"image and the CI smoke test greps for them): {offenders}")

    def test_the_dockerfile_still_copies_it(self):
        """If the COPY is ever removed, these tests should stop being load-bearing
        rather than silently guarding nothing."""
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertTrue(
            re.search(r"^COPY\s+config\s+/app/config", dockerfile, re.M),
            "Dockerfile no longer copies config/ — if that is intentional, this "
            "test file and the sample config can go too.")


if __name__ == "__main__":
    unittest.main()

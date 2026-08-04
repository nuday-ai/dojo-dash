"""dojo-dash — a config-as-code reporting dashboard for DefectDojo.

Renders live DefectDojo findings into a self-contained HTML posture dashboard and a
SOC 2 evidence report, served by a tiny stdlib HTTP server (no framework, no database
— it reads the DefectDojo REST API only). Everything visible is driven by a single
YAML config; branding, repositories, environments and the control map are all
declarative.

It also renders a COMPLIANCE report from a checked-in control registry
(`control-registry` / `control-registry-summary` sections) which reads no DefectDojo
data at all — deliberately, because framework evidence is a claim about a commit and
must not drift under an assessor between submission and review. See the README and
docs/ for configuration and deployment.
"""

__version__ = "0.5.0"

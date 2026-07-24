"""dojo-dash — a config-as-code reporting dashboard for DefectDojo.

Renders live DefectDojo findings into a self-contained HTML posture dashboard and a
SOC 2 / CASA evidence report, served by a tiny stdlib HTTP server (no framework, no
database — it reads the DefectDojo REST API only). Everything visible is driven by a
single YAML config; branding, repositories, environments and the control map are all
declarative. See the README and docs/ for configuration and deployment.
"""

__version__ = "0.1.4"

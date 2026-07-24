# dojo-dash — a tiny, self-contained DefectDojo reporting server.
# No scanners, no DefectDojo code: just Python stdlib + requests + pyyaml.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install the package (deps: requests, pyyaml, tzdata) plus the optional MongoDB dedup
# backend (pymongo). Copy metadata + source, then pip install.
COPY pyproject.toml README.md ./
COPY dojo_dash ./dojo_dash
RUN pip install .[mongodb]

# Bake the sample config so the image runs standalone. Mount your own over /app/config
# (or set DOJO_DASH_CONFIG) to point at a real product type / branding / control map.
COPY config /app/config

ENV DOJO_DASH_CONFIG=/app/config/reports.yaml \
    REPORT_PORT=8091

# Run as a non-root user.
RUN useradd --system --uid 10001 --create-home dojo && chown -R dojo /app
USER dojo

EXPOSE 8091

# DB-independent health check — 200 as soon as the process is up, before DefectDojo boots.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8091/report/health',timeout=3).status==200 else 1)"

ENTRYPOINT ["dojo-dash"]
CMD ["serve"]

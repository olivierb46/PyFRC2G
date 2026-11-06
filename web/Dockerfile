# PyFRC2G-Web - runtime image: Python, Graphviz and the dependencies only.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Graphviz provides the "dot" executable; DejaVu fonts give readable graph labels.
RUN apt-get update \
 && apt-get install -y --no-install-recommends graphviz fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Unprivileged user; /data holds the encrypted database (mount a volume).
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin pyfrc2g \
 && mkdir -p /data /app/pyfrc2g /app/pyfrc2g-web \
 && chown pyfrc2g /data
USER pyfrc2g
WORKDIR /data
VOLUME ["/data"]

# Mount points of the code: /app/pyfrc2g/pyfrc2g (engine) and /app/pyfrc2g-web/pyfrc2g_web.
ENV PYTHONPATH=/app/pyfrc2g:/app/pyfrc2g-web \
    PYFRC2G_DATA_DIR=/data \
    XDG_CACHE_HOME=/tmp/cache \
    PYFRC2G_WEB_HOST=0.0.0.0 \
    PYFRC2G_WEB_PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4)" || exit 1

ENTRYPOINT ["python", "-m", "pyfrc2g_web"]

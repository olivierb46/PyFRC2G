# PyFRC2G engine - command line image, Graphviz included (build from the engine/ folder).
# (The web application is in the web/ folder of this repository.)
#
#   cd engine && docker build -t pyfrc2g .
#   # One-shot analysis of a backup, results in ./results:
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/data" pyfrc2g --backup config.xml
#   # Scheduled API analysis (credentials in .env, results in a volume):
#   docker run -d --env-file .env -v pyfrc2g-results:/data pyfrc2g --api --every 6h

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Graphviz provides the "dot" executable; DejaVu fonts give readable graph labels.
RUN apt-get update \
 && apt-get install -y --no-install-recommends graphviz fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY pyfrc2g ./pyfrc2g
RUN pip install . && rm -rf build *.egg-info
COPY examples ./examples

# Unprivileged user; /data is the working directory (results/ is written there).
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin pyfrc2g \
 && mkdir -p /data \
 && chown pyfrc2g /data
USER pyfrc2g
WORKDIR /data
VOLUME ["/data"]
ENV XDG_CACHE_HOME=/tmp/cache

ENTRYPOINT ["pyfrc2g"]
CMD ["--help"]

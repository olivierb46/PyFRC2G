FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends graphviz \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup --system appgroup \
 && adduser --system --ingroup appgroup --shell /usr/sbin/nologin appuser

COPY . .
RUN mkdir -p /app/results \
 && chown -R appuser:appgroup /app
USER appuser

CMD ["python", "pyfrc2g.py"]

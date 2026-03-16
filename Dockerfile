FROM python:3.10-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends graphviz \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir requests graphviz reportlab

CMD ["python", "pyfrc2g.py"]

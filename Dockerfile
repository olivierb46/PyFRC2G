FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    graphviz \
    nginx \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup --system appgroup \
 && adduser --system --ingroup appgroup --shell /usr/sbin/nologin appuser

COPY . .

RUN mkdir -p /app/results \
 && chown -R appuser:appgroup /app

# nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# startup script
COPY docker-start.sh /docker-start.sh
RUN chmod +x /docker-start.sh

USER appuser

EXPOSE 8080

CMD ["/docker-start.sh"]

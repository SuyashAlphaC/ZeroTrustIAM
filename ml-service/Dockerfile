FROM python:3.11-slim AS builder
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim AS runtime
RUN groupadd --gid 10001 ztiam \
 && useradd --uid 10001 --gid ztiam --shell /bin/sh --create-home ztiam

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MODEL_DIR=/app/models \
    PATH=/install/bin:$PATH \
    PYTHONPATH=/install/lib/python3.11/site-packages

WORKDIR /app
COPY --from=builder /install /install
COPY *.py ./
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
 && mkdir -p /app/models \
 && chown -R 10001:10001 /app

# Start as root so entrypoint can chown the models volume, then drop to ztiam
EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=30s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3).status==200 else 1)" || exit 1

ENTRYPOINT ["/entrypoint.sh"]

#!/bin/sh
set -e
# Volume mounts are root-owned; ensure MODEL_DIR is writable by the app user.
mkdir -p "${MODEL_DIR:-/app/models}"
if [ "$(id -u)" = "0" ]; then
  chown -R 10001:10001 "${MODEL_DIR:-/app/models}" || true
  exec su -s /bin/sh ztiam -c "exec uvicorn app:app --host 0.0.0.0 --port 5000"
fi
exec uvicorn app:app --host 0.0.0.0 --port 5000

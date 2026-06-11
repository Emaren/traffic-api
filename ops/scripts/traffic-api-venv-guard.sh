#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/var/www/Traffic/traffic-api"
VENV="$APP_DIR/.venv"
PY="$VENV/bin/python3"
LOG_TAG="traffic-api-venv-guard"

log() {
  logger -t "$LOG_TAG" "$*"
  echo "$*"
}

cd "$APP_DIR"

healthy=1

if [ ! -x "$PY" ]; then
  healthy=0
elif ! "$PY" - <<'PY' >/dev/null 2>&1
import uvicorn
import fastapi
PY
then
  healthy=0
fi

if [ "$healthy" = "1" ]; then
  log "venv healthy"
  exit 0
fi

log "venv unhealthy; rebuilding"

rm -rf "$VENV"
python3 -m venv "$VENV"
"$PY" -m pip install --upgrade pip wheel setuptools
"$PY" -m pip install -r requirements.txt
chown -R tony:tony "$VENV"

log "venv rebuilt successfully"

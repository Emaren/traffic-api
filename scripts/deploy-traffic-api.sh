#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/var/www/Traffic/traffic-api"
PY="$APP_DIR/.venv/bin/python3"
VENV_GUARD="/var/www/Traffic/ops/traffic-api-venv-guard.sh"
ARCHIVE_URL="https://traffic.tokentap.ca/api/visits/history?limit=25&classification=human_visible&projects=aoe2hdbets&range_key=all&offset=0"

cd "$APP_DIR"

echo "== git status before deploy =="
git status --short --branch

echo
echo "== venv guard =="
if [ ! -x "$VENV_GUARD" ]; then
  echo "Missing venv guard: $VENV_GUARD" >&2
  exit 1
fi
"$VENV_GUARD"

if [ ! -x "$PY" ]; then
  echo "Python still missing after venv guard: $PY" >&2
  exit 1
fi

echo
echo "== python version =="
"$PY" --version

echo
echo "== python compile gate =="
"$PY" -m compileall app scripts

echo
echo "== import gate =="
"$PY" -c 'import fastapi, uvicorn; from app.main import app; print("imports ok:", bool(app))'

echo
echo "== restart traffic-api =="
systemctl restart traffic-api.service
sleep 12

echo
echo "== service status =="
systemctl status traffic-api.service --no-pager -l | sed -n '1,90p'

echo
echo "== local API smoke =="
curl -sS -m 10 http://127.0.0.1:3345/api/healthz && echo

echo
echo "== public API smoke =="
curl -sS -m 10 https://traffic.tokentap.ca/api/healthz && echo

echo
echo "== archive smoke =="
/usr/bin/time -f "elapsed=%E" curl -sS -m 20 "$ARCHIVE_URL" -o /tmp/traffic-api-deploy-archive-smoke.json

"$PY" -c '
import json
from pathlib import Path

p = Path("/tmp/traffic-api-deploy-archive-smoke.json")
d = json.loads(p.read_text())
items = d.get("items", [])
page_lengths = [len(item.get("page_sequence") or []) for item in items]

print("ok:", d.get("ok"))
print("coverage_mode:", d.get("coverage_mode"))
print("total:", d.get("total"))
print("items:", len(items))
print("max_page_sequence:", max(page_lengths or [0]))
print("bytes:", p.stat().st_size)

if not d.get("ok"):
    raise SystemExit("archive smoke failed: ok=false")
if d.get("coverage_mode") != "session_archive":
    raise SystemExit(f"archive smoke failed: coverage_mode={d.get(\"coverage_mode\")}")
'

echo
echo "== frontend smoke =="
WEB_CODE="$(curl -sS -m 15 -o /tmp/traffic-api-deploy-web-smoke.html -w '%{http_code}' https://traffic.tokentap.ca/)"
echo "web_http_code=$WEB_CODE"
if [ "$WEB_CODE" != "200" ]; then
  echo "frontend smoke failed: HTTP $WEB_CODE" >&2
  exit 1
fi

echo
echo "deploy complete"

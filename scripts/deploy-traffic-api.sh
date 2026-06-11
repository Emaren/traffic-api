#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/var/www/Traffic/traffic-api"
ARCHIVE_URL="https://traffic.tokentap.ca/api/visits/history?limit=25&classification=human_visible&projects=aoe2hdbets&range_key=all&offset=0"

cd "$APP_DIR"

echo "== git status before deploy =="
git status --short --branch

echo
echo "== python compile gate =="
.venv/bin/python3 -m compileall app scripts

echo
echo "== import gate =="
.venv/bin/python3 - <<'PY'
import fastapi
import uvicorn
from app.main import app
print("imports ok:", bool(app))
PY

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
/usr/bin/time -f "elapsed=%E" \
curl -sS -m 20 "$ARCHIVE_URL" \
  -o /tmp/traffic-api-deploy-archive-smoke.json

.venv/bin/python3 - <<'PY'
import json
from pathlib import Path

d = json.loads(Path("/tmp/traffic-api-deploy-archive-smoke.json").read_text())
items = d.get("items", [])
page_lengths = [len(item.get("page_sequence") or []) for item in items]

print("ok:", d.get("ok"))
print("coverage_mode:", d.get("coverage_mode"))
print("total:", d.get("total"))
print("items:", len(items))
print("max_page_sequence:", max(page_lengths or [0]))
print("bytes:", Path("/tmp/traffic-api-deploy-archive-smoke.json").stat().st_size)

if not d.get("ok"):
    raise SystemExit("archive smoke failed: ok=false")
if d.get("coverage_mode") != "session_archive":
    raise SystemExit(f"archive smoke failed: coverage_mode={d.get('coverage_mode')}")
PY

echo
echo "== frontend smoke =="
curl -sS -m 15 -D- https://traffic.tokentap.ca/ -o /tmp/traffic-api-deploy-web-smoke.html | sed -n '1,12p'

echo
echo "deploy complete"

#!/usr/bin/env bash
set -u

LOG_TAG="traffic-watchdog"

log() {
  logger -t "$LOG_TAG" "$*"
  echo "$*"
}

failures=0

check_url() {
  local label="$1"
  local url="$2"
  local timeout="${3:-10}"

  local code
  code="$(curl -k -sS -m "$timeout" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo "000")"

  if [ "$code" = "200" ]; then
    log "OK $label $code"
    return 0
  fi

  log "FAIL $label $code $url"
  return 1
}

echo "== $(date -Is) Traffic watchdog =="

if ! check_url "local-web" "http://127.0.0.1:3045/" 8; then
  failures=$((failures + 1))
  log "Restarting traffic-web.service after local-web failure"
  systemctl restart traffic-web.service || true
  sleep 8
fi

if ! check_url "public-web" "https://traffic.tokentap.ca/" 12; then
  failures=$((failures + 1))
  log "Restarting traffic-web.service after public-web failure"
  systemctl restart traffic-web.service || true
  sleep 8
fi

if ! check_url "api-health" "http://127.0.0.1:3345/api/healthz" 8; then
  failures=$((failures + 1))
  log "Restarting traffic-api.service after api-health failure"
  systemctl restart traffic-api.service || true
  sleep 8
fi

if ! check_url "public-archive" "https://traffic.tokentap.ca/api/visits/history?limit=1&classification=human_visible&projects=aoe2hdbets&range_key=all&offset=0" 12; then
  failures=$((failures + 1))
  log "Archive endpoint failed; API may be degraded"
fi

log "watchdog complete failures=$failures"
exit 0

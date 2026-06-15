from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Mapping
from urllib.parse import urlparse

from app.services.traffic.config import PERSIST_DB_PATH, PERSIST_ENABLED
from app.services.traffic.geo import get_geo_details
from app.services.traffic.known_visitors import known_visitor_for_ip
from app.services.traffic.normalize import is_allowed_host, normalize_host, normalize_path, project_for_host
from app.services.traffic.parse import iso_now

_EVENT_NAME_RE = re.compile(r"^[a-zA-Z0-9_:.:-]{1,80}$")
_MAX_TEXT = 240

CORE_EVENT_TYPES = {
    "page_view",
    "heartbeat",
    "scroll_milestone",
    "click",
    "outbound_click",
    "rage_click",
    "page_hide",
    "visibility_change",
}


def _connect() -> sqlite3.Connection:
    PERSIST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(PERSIST_DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS traffic_browser_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            host TEXT NOT NULL,
            project_slug TEXT NOT NULL,
            project_name TEXT NOT NULL,
            path TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            referrer TEXT NOT NULL DEFAULT '',
            visitor_id TEXT NOT NULL DEFAULT '',
            session_id TEXT NOT NULL DEFAULT '',
            page_view_id TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL,
            viewport_width INTEGER,
            viewport_height INTEGER,
            document_height INTEGER,
            scroll_y INTEGER,
            scroll_depth_pct INTEGER,
            max_scroll_depth_pct INTEGER,
            click_x INTEGER,
            click_y INTEGER,
            click_text TEXT NOT NULL DEFAULT '',
            click_label TEXT NOT NULL DEFAULT '',
            click_href TEXT NOT NULL DEFAULT '',
            click_selector TEXT NOT NULL DEFAULT '',
            element_role TEXT NOT NULL DEFAULT '',
            element_tag TEXT NOT NULL DEFAULT '',
            visible_ms INTEGER,
            dwell_ms INTEGER,
            user_agent TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            country_code TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            area TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_traffic_browser_events_received
            ON traffic_browser_events(received_at DESC);

        CREATE INDEX IF NOT EXISTS idx_traffic_browser_events_project_received
            ON traffic_browser_events(project_slug, received_at DESC);

        CREATE INDEX IF NOT EXISTS idx_traffic_browser_events_session_received
            ON traffic_browser_events(session_id, received_at DESC);

        CREATE INDEX IF NOT EXISTS idx_traffic_browser_events_visitor_received
            ON traffic_browser_events(visitor_id, received_at DESC);
        """
    )

    existing_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(traffic_browser_events)").fetchall()
    }
    for column_name in ("country_code", "country", "area", "city"):
        if column_name not in existing_columns:
            connection.execute(
                f"ALTER TABLE traffic_browser_events ADD COLUMN {column_name} TEXT NOT NULL DEFAULT ''"
            )


def _clean_text(value: Any, max_len: int = _MAX_TEXT) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:max_len]


def _clean_event_type(value: Any) -> str:
    event_type = _clean_text(value, 80)
    if not event_type:
        raise ValueError("event_type is required")
    if event_type not in CORE_EVENT_TYPES and not _EVENT_NAME_RE.match(event_type):
        raise ValueError("event_type is invalid")
    return event_type


def _int_or_none(value: Any, *, minimum: int | None = None, maximum: int | None = None) -> int | None:
    if value is None or value == "":
        return None
    try:
        parsed = int(float(value))
    except Exception:
        return None
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _host_from_headers(headers: Mapping[str, str]) -> str:
    origin = headers.get("origin") or headers.get("Origin") or ""
    if origin:
        try:
            return normalize_host(urlparse(origin).netloc or origin)
        except Exception:
            return normalize_host(origin)

    referrer = headers.get("referer") or headers.get("Referer") or ""
    if referrer:
        try:
            return normalize_host(urlparse(referrer).netloc or referrer)
        except Exception:
            return normalize_host(referrer)

    return ""


def _client_ip(headers: Mapping[str, str], fallback: str | None) -> str:
    forwarded = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or ""
    if forwarded:
        return _clean_text(forwarded.split(",")[0], 80)
    real_ip = headers.get("x-real-ip") or headers.get("X-Real-IP") or ""
    if real_ip:
        return _clean_text(real_ip, 80)
    return _clean_text(fallback, 80)


def _compact_payload(payload: dict[str, Any]) -> str:
    allowed_extra = {
        "visibility_state",
        "scroll_milestone",
        "timezone",
        "language",
        "screen_width",
        "screen_height",
        "device_pixel_ratio",
        "traffic_event_label",
    }
    compact = {key: payload.get(key) for key in sorted(allowed_extra) if key in payload}
    return json.dumps(compact, separators=(",", ":"), ensure_ascii=False)


def record_browser_event(
    payload: dict[str, Any],
    *,
    headers: Mapping[str, str],
    client_host: str | None = None,
) -> dict[str, Any]:
    if not PERSIST_ENABLED:
        return {"ok": True, "stored": False, "reason": "persistence_disabled", "generated_at": iso_now()}

    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    header_host = _host_from_headers(headers)
    host = normalize_host(_clean_text(payload.get("host"), 160) or header_host)
    if not is_allowed_host(host):
        raise ValueError(f"host is not allowed: {host}")

    project = project_for_host(host)
    event_type = _clean_event_type(payload.get("event_type"))
    received_at = iso_now()
    occurred_at = _clean_text(payload.get("occurred_at"), 80) or received_at
    path = normalize_path(_clean_text(payload.get("path"), 500) or "/")
    ip = _client_ip(headers, client_host)
    geo = get_geo_details(ip)

    row = {
        "received_at": received_at,
        "occurred_at": occurred_at,
        "host": host,
        "project_slug": project.get("slug") or "unknown",
        "project_name": project.get("name") or "Unknown",
        "path": path,
        "title": _clean_text(payload.get("title"), 180),
        "referrer": _clean_text(payload.get("referrer"), 500),
        "visitor_id": _clean_text(payload.get("visitor_id"), 100),
        "session_id": _clean_text(payload.get("session_id"), 100),
        "page_view_id": _clean_text(payload.get("page_view_id"), 100),
        "event_type": event_type,
        "viewport_width": _int_or_none(payload.get("viewport_width"), minimum=0, maximum=20000),
        "viewport_height": _int_or_none(payload.get("viewport_height"), minimum=0, maximum=20000),
        "document_height": _int_or_none(payload.get("document_height"), minimum=0, maximum=500000),
        "scroll_y": _int_or_none(payload.get("scroll_y"), minimum=0, maximum=500000),
        "scroll_depth_pct": _int_or_none(payload.get("scroll_depth_pct"), minimum=0, maximum=100),
        "max_scroll_depth_pct": _int_or_none(payload.get("max_scroll_depth_pct"), minimum=0, maximum=100),
        "click_x": _int_or_none(payload.get("click_x"), minimum=0, maximum=20000),
        "click_y": _int_or_none(payload.get("click_y"), minimum=0, maximum=20000),
        "click_text": _clean_text(payload.get("click_text"), 120),
        "click_label": _clean_text(payload.get("click_label"), 160),
        "click_href": _clean_text(payload.get("click_href"), 500),
        "click_selector": _clean_text(payload.get("click_selector"), 240),
        "element_role": _clean_text(payload.get("element_role"), 80),
        "element_tag": _clean_text(payload.get("element_tag"), 40).lower(),
        "visible_ms": _int_or_none(payload.get("visible_ms"), minimum=0, maximum=86_400_000),
        "dwell_ms": _int_or_none(payload.get("dwell_ms"), minimum=0, maximum=86_400_000),
        "user_agent": _clean_text(headers.get("user-agent") or headers.get("User-Agent"), 500),
        "ip": ip,
        "country_code": _clean_text(geo.get("country_code"), 8),
        "country": _clean_text(geo.get("country"), 120),
        "area": _clean_text(geo.get("area"), 120),
        "city": _clean_text(geo.get("city"), 120),
        "payload_json": _compact_payload(payload),
    }

    with _connect() as connection:
        _ensure_schema(connection)
        cursor = connection.execute(
            """
            INSERT INTO traffic_browser_events (
                received_at, occurred_at, host, project_slug, project_name, path, title, referrer,
                visitor_id, session_id, page_view_id, event_type, viewport_width, viewport_height,
                document_height, scroll_y, scroll_depth_pct, max_scroll_depth_pct, click_x, click_y,
                click_text, click_label, click_href, click_selector, element_role, element_tag,
                visible_ms, dwell_ms, user_agent, ip, country_code, country, area, city, payload_json
            ) VALUES (
                :received_at, :occurred_at, :host, :project_slug, :project_name, :path, :title, :referrer,
                :visitor_id, :session_id, :page_view_id, :event_type, :viewport_width, :viewport_height,
                :document_height, :scroll_y, :scroll_depth_pct, :max_scroll_depth_pct, :click_x, :click_y,
                :click_text, :click_label, :click_href, :click_selector, :element_role, :element_tag,
                :visible_ms, :dwell_ms, :user_agent, :ip, :country_code, :country, :area, :city, :payload_json
            )
            """,
            row,
        )
        connection.commit()
        event_id = int(cursor.lastrowid)

    return {
        "ok": True,
        "stored": True,
        "event_id": event_id,
        "event_type": event_type,
        "project_slug": row["project_slug"],
        "generated_at": received_at,
    }


def _enrich_browser_event_row(row: sqlite3.Row) -> dict[str, Any]:
    event = dict(row)
    ip = str(event.get("ip") or "").strip()

    if ip and not event.get("country"):
        geo = get_geo_details(ip)
        event["country_code"] = _clean_text(geo.get("country_code"), 8)
        event["country"] = _clean_text(geo.get("country"), 120)
        event["area"] = _clean_text(geo.get("area"), 120)
        event["city"] = _clean_text(geo.get("city"), 120)

    known_visitor = known_visitor_for_ip(ip)
    if known_visitor:
        event["known_visitor_label"] = _clean_text(known_visitor.get("label"), 120)
        event["known_visitor_detail"] = _clean_text(known_visitor.get("detail"), 120)
        event["known_visitor_kind"] = _clean_text(known_visitor.get("identity_kind"), 40)
    else:
        event["known_visitor_label"] = ""
        event["known_visitor_detail"] = ""
        event["known_visitor_kind"] = ""

    return event


def list_recent_browser_events(
    limit: int = 50,
    project_slug: str | None = None,
    before_received_at: str | None = None,
    since_hours: int = 24,
) -> list[dict[str, Any]]:
    if not PERSIST_ENABLED:
        return []

    limit = max(1, min(int(limit or 50), 200))
    since_hours = max(1, min(int(since_hours or 24), 168))

    clauses = ["datetime(received_at) >= datetime('now', ?)"]
    params: list[Any] = [f"-{since_hours} hours"]

    if project_slug:
        clauses.append("project_slug = ?")
        params.append(project_slug)

    if before_received_at:
        clauses.append("received_at < ?")
        params.append(before_received_at)

    where_sql = " AND ".join(clauses)

    with _connect() as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            f"""
            SELECT *
            FROM traffic_browser_events
            WHERE {where_sql}
            ORDER BY received_at DESC, id DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()

    return [_enrich_browser_event_row(row) for row in rows]


def build_beacon_javascript() -> str:
    return r'''
(function(){
  if (window.__trafficBeaconLoaded) return;
  window.__trafficBeaconLoaded = true;

  var script = document.currentScript;
  var endpoint = script && script.dataset && script.dataset.endpoint
    ? script.dataset.endpoint
    : new URL('/api/ingest/browser-event', script ? script.src : 'https://traffic.tokentap.ca/api/beacon.js').toString();

  var project = script && script.dataset ? (script.dataset.project || '') : '';
  var thresholds = [25,50,75,90,100];
  var sentThresholds = {};
  var maxScroll = 0;
  var pageStartedAt = Date.now();
  var visibleStartedAt = document.visibilityState === 'visible' ? Date.now() : 0;
  var visibleMs = 0;

  function id(prefix){
    return prefix + '_' + Math.random().toString(36).slice(2) + '_' + Date.now().toString(36);
  }

  function storageGetSet(store, key, prefix){
    try {
      var value = store.getItem(key);
      if (!value) { value = id(prefix); store.setItem(key, value); }
      return value;
    } catch(e) { return id(prefix); }
  }

  var visitorId = storageGetSet(window.localStorage, 'traffic_visitor_id', 'v');
  var sessionId = storageGetSet(window.sessionStorage, 'traffic_session_id', 's');
  var pageViewId = id('pv');

  function nowVisibleMs(){
    var total = visibleMs;
    if (visibleStartedAt) total += Date.now() - visibleStartedAt;
    return Math.max(0, Math.round(total));
  }

  function docHeight(){
    var b = document.body || {};
    var e = document.documentElement || {};
    return Math.max(b.scrollHeight||0, b.offsetHeight||0, e.clientHeight||0, e.scrollHeight||0, e.offsetHeight||0);
  }

  function scrollPct(){
    var h = docHeight();
    var vh = window.innerHeight || 0;
    if (!h || h <= vh) return 100;
    return Math.max(0, Math.min(100, Math.round(((window.scrollY || window.pageYOffset || 0) + vh) / h * 100)));
  }

  function basePayload(type){
    maxScroll = Math.max(maxScroll, scrollPct());
    return {
      event_type: type,
      occurred_at: new Date().toISOString(),
      host: window.location.hostname,
      path: window.location.pathname + window.location.search,
      title: document.title || '',
      referrer: document.referrer || '',
      project_slug: project,
      visitor_id: visitorId,
      session_id: sessionId,
      page_view_id: pageViewId,
      viewport_width: window.innerWidth || 0,
      viewport_height: window.innerHeight || 0,
      document_height: docHeight(),
      scroll_y: Math.max(0, Math.round(window.scrollY || window.pageYOffset || 0)),
      scroll_depth_pct: scrollPct(),
      max_scroll_depth_pct: maxScroll,
      visible_ms: nowVisibleMs(),
      dwell_ms: Math.max(0, Date.now() - pageStartedAt),
      timezone: Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions ? Intl.DateTimeFormat().resolvedOptions().timeZone : '',
      language: navigator.language || '',
      screen_width: screen.width || 0,
      screen_height: screen.height || 0,
      device_pixel_ratio: window.devicePixelRatio || 1
    };
  }

  function send(type, extra, useBeacon){
    var payload = basePayload(type);
    if (extra) for (var k in extra) payload[k] = extra[k];
    var body = JSON.stringify(payload);

    if (useBeacon && navigator.sendBeacon) {
      try {
        navigator.sendBeacon(endpoint, new Blob([body], {type: 'application/json'}));
        return;
      } catch(e) {}
    }

    try {
      fetch(endpoint, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:body,
        keepalive: !!useBeacon,
        credentials:'omit'
      }).catch(function(){});
    } catch(e) {}
  }

  function selectorFor(el){
    if (!el || !el.tagName) return '';
    var out = el.tagName.toLowerCase();
    if (el.id) return out + '#' + el.id.slice(0,80);
    var label = el.getAttribute('data-traffic-label') || el.getAttribute('aria-label') || '';
    if (label) out += '[label="' + label.slice(0,80).replace(/"/g,'') + '"]';
    return out;
  }

  function clickTarget(start){
    if (!start || !start.closest) return null;
    return start.closest('[data-traffic-event],[data-traffic-label],a,button,[role="button"],input[type="button"],input[type="submit"]');
  }

  send('page_view');

  setInterval(function(){
    if (document.visibilityState === 'visible') send('heartbeat');
  }, 15000);

  var ticking = false;
  window.addEventListener('scroll', function(){
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function(){
      ticking = false;
      var pct = scrollPct();
      maxScroll = Math.max(maxScroll, pct);
      thresholds.forEach(function(t){
        if (pct >= t && !sentThresholds[t]) {
          sentThresholds[t] = true;
          send('scroll_milestone', {scroll_milestone: t});
        }
      });
    });
  }, {passive:true});

  document.addEventListener('click', function(ev){
    var el = clickTarget(ev.target);
    if (!el) return;

    var href = el.href || el.getAttribute('href') || '';
    var explicit = el.getAttribute('data-traffic-event') || '';
    var label = el.getAttribute('data-traffic-label') || el.getAttribute('aria-label') || el.innerText || el.textContent || '';
    label = (label || '').replace(/\s+/g,' ').trim().slice(0,120);

    var type = explicit || (href && new URL(href, window.location.href).hostname !== window.location.hostname ? 'outbound_click' : 'click');

    send(type, {
      click_x: Math.round(ev.clientX || 0),
      click_y: Math.round(ev.clientY || 0),
      click_text: label,
      click_label: label,
      click_href: href ? new URL(href, window.location.href).toString().slice(0,500) : '',
      click_selector: selectorFor(el),
      element_role: el.getAttribute('role') || '',
      element_tag: (el.tagName || '').toLowerCase(),
      traffic_event_label: label
    });
  }, true);

  document.addEventListener('visibilitychange', function(){
    if (document.visibilityState === 'hidden') {
      if (visibleStartedAt) { visibleMs += Date.now() - visibleStartedAt; visibleStartedAt = 0; }
      send('visibility_change', {visibility_state:'hidden'}, true);
    } else {
      visibleStartedAt = Date.now();
      send('visibility_change', {visibility_state:'visible'});
    }
  });

  window.addEventListener('pagehide', function(){ send('page_hide', {}, true); });
})();
'''.strip() + "\n"

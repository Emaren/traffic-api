from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager
import json
import signal
from time import monotonic
import threading
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from app.services.traffic.overview import clear_session_snapshot_cache, warm_session_snapshots
from app.services.traffic.config import (
    ADMIN_API_KEY,
    NOTIFICATION_BATCH_LIMIT,
    NOTIFICATION_LOOP_SECONDS,
    PROJECTS,
)
from app.services.traffic.notifications import (
    admin_api_configured,
    build_notification_dashboard,
    create_operator_identity,
    create_notification_mute,
    delete_operator_identity,
    delete_notification_mute,
    delete_web_push_subscription,
    process_notification_batch,
    register_web_push_subscription,
    send_test_notification,
    update_notification_settings,
)
from app.services.traffic.parse import iso_now
from app.services.traffic.visibility import (
    create_visibility_rule,
    delete_visibility_rule,
    list_visibility_rules,
)
from app.services.traffic_core import (
    build_live_visitors,
    build_overview,
    build_project_detail,
    build_project_graph,
    build_project_live_feed,
    build_visitor_profile,
    build_project_human_series,
    build_visits_history,
)

DEFAULT_PROJECT_DETAIL_BUCKET_MINUTES = 30
LONG_RANGE_CACHE_TTL_SECONDS = 60.0
MID_RANGE_CACHE_TTL_SECONDS = 40.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    shutdown_event = asyncio.Event()
    app.state.shutdown_event = shutdown_event
    app.state.active_streams = 0
    app.state.notification_loop_state = {
        "mode": "booting",
        "checked": 0,
        "delivered": 0,
        "suppressed": 0,
        "errors": 0,
        "last_run_at": None,
    }

    previous_handlers: dict[signal.Signals, object] = {}
    loop = asyncio.get_running_loop()
    notification_task: asyncio.Task | None = None
    warm_cache_task: asyncio.Task | None = None

    def request_shutdown(signum: int, _frame) -> None:
        loop.call_soon_threadsafe(shutdown_event.set)
        previous = previous_handlers.get(signal.Signals(signum))
        if callable(previous):
            previous(signum, _frame)

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, request_shutdown)

    notification_task = asyncio.create_task(notification_worker(app))
    warm_cache_task = None

    try:
        yield
    finally:
        shutdown_event.set()
        if notification_task is not None:
            try:
                await asyncio.wait_for(notification_task, timeout=NOTIFICATION_LOOP_SECONDS + 5)
            except asyncio.TimeoutError:
                notification_task.cancel()
        if warm_cache_task is not None and not warm_cache_task.done():
            warm_cache_task.cancel()
        if threading.current_thread() is threading.main_thread():
            for signum, previous in previous_handlers.items():
                signal.signal(signum, previous)


app = FastAPI(title="Traffic API", version="0.3.0", lifespan=lifespan)

OVERVIEW_CACHE_TTL_SECONDS = 20.0
SERIES_CACHE_TTL_SECONDS = 20.0
LIVE_VISITORS_CACHE_TTL_SECONDS = 5.0
VISITS_HISTORY_CACHE_TTL_SECONDS = 30.0
PROJECT_DETAIL_CACHE_TTL_SECONDS = 30.0
VISITOR_PROFILE_CACHE_TTL_SECONDS = 30.0

_response_cache_lock = threading.Lock()
_RESPONSE_CACHE_MAX_KEYS = 32
_RESPONSE_CACHE_STALE_SECONDS = 300.0
_response_cache: dict[tuple[str, tuple[tuple[str, Any], ...]], tuple[float, Any]] = {}
_response_cache_refreshing: set[tuple[str, tuple[tuple[str, Any], ...]]] = set()
_response_cache_events: dict[
    tuple[str, tuple[tuple[str, Any], ...]],
    threading.Event,
] = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://traffic.tokentap.ca",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


def get_shutdown_event(app: FastAPI) -> asyncio.Event:
    shutdown_event = getattr(app.state, "shutdown_event", None)
    if isinstance(shutdown_event, asyncio.Event):
        return shutdown_event

    fallback_event = asyncio.Event()
    app.state.shutdown_event = fallback_event
    return fallback_event


def get_active_streams(app: FastAPI) -> int:
    active_streams = getattr(app.state, "active_streams", 0)
    return active_streams if isinstance(active_streams, int) else 0


def get_notification_loop_state(app: FastAPI) -> dict[str, object]:
    loop_state = getattr(app.state, "notification_loop_state", None)
    if isinstance(loop_state, dict):
        return loop_state
    fallback = {
        "mode": "booting",
        "checked": 0,
        "delivered": 0,
        "suppressed": 0,
        "errors": 0,
        "last_run_at": None,
    }
    app.state.notification_loop_state = fallback
    return fallback


def _prune_response_cache(
    now: float,
    *,
    keep_key: tuple[str, tuple[tuple[str, Any], ...]] | None = None,
) -> None:
    expired_keys = [
        key
        for key, (created_at, _payload) in _response_cache.items()
        if key != keep_key and now - created_at > _RESPONSE_CACHE_STALE_SECONDS
    ]
    for key in expired_keys:
        _response_cache.pop(key, None)
        _response_cache_refreshing.discard(key)
        event = _response_cache_events.pop(key, None)
        if event is not None:
            event.set()

    if len(_response_cache) <= _RESPONSE_CACHE_MAX_KEYS:
        return

    removable = sorted(
        (
            (created_at, key)
            for key, (created_at, _payload) in _response_cache.items()
            if key != keep_key
        ),
        key=lambda item: item[0],
    )

    while len(_response_cache) > _RESPONSE_CACHE_MAX_KEYS and removable:
        _created_at, key = removable.pop(0)
        _response_cache.pop(key, None)
        _response_cache_refreshing.discard(key)
        event = _response_cache_events.pop(key, None)
        if event is not None:
            event.set()


def cached_response(
    cache_name: str,
    *,
    ttl_seconds: float,
    builder: Callable[[], Any],
    **params: Any,
) -> Any:
    cache_key = (cache_name, tuple(sorted(params.items())))
    now = monotonic()
    wait_event: threading.Event | None = None
    build_here = False

    with _response_cache_lock:
        _prune_response_cache(now, keep_key=cache_key)
        cached = _response_cache.get(cache_key)
        if cached and now - cached[0] < ttl_seconds:
            return cached[1]

        if cached:
            if cache_key not in _response_cache_refreshing:
                _response_cache_refreshing.add(cache_key)
                refresh_event = threading.Event()
                _response_cache_events[cache_key] = refresh_event

                def refresh_in_background() -> None:
                    try:
                        payload = builder()
                        with _response_cache_lock:
                            tick = monotonic()
                            _response_cache[cache_key] = (tick, payload)
                            _prune_response_cache(tick, keep_key=cache_key)
                    finally:
                        with _response_cache_lock:
                            _response_cache_refreshing.discard(cache_key)
                            _response_cache_events.pop(cache_key, refresh_event).set()

                threading.Thread(target=refresh_in_background, daemon=True).start()
            return cached[1]

        if cache_key in _response_cache_refreshing:
            wait_event = _response_cache_events.get(cache_key)
        else:
            _response_cache_refreshing.add(cache_key)
            wait_event = threading.Event()
            _response_cache_events[cache_key] = wait_event
            build_here = True

    if not build_here and wait_event is not None:
        wait_event.wait(timeout=max(ttl_seconds, 5.0))
        with _response_cache_lock:
            tick = monotonic()
            _prune_response_cache(tick, keep_key=cache_key)
            cached = _response_cache.get(cache_key)
            if cached:
                return cached[1]
            if cache_key not in _response_cache_refreshing:
                _response_cache_refreshing.add(cache_key)
                wait_event = threading.Event()
                _response_cache_events[cache_key] = wait_event
                build_here = True

    if not build_here:
        with _response_cache_lock:
            _response_cache_refreshing.add(cache_key)
            wait_event = threading.Event()
            _response_cache_events[cache_key] = wait_event
        build_here = True

    try:
        payload = builder()
    except Exception:
        with _response_cache_lock:
            _response_cache_refreshing.discard(cache_key)
            _response_cache_events.pop(cache_key, wait_event or threading.Event()).set()
        raise

    with _response_cache_lock:
        tick = monotonic()
        _response_cache[cache_key] = (tick, payload)
        _prune_response_cache(tick, keep_key=cache_key)
        _response_cache_refreshing.discard(cache_key)
        _response_cache_events.pop(cache_key, wait_event or threading.Event()).set()

    return payload


def clear_response_cache() -> None:
    with _response_cache_lock:
        _response_cache.clear()
        _response_cache_refreshing.clear()
        _response_cache_events.clear()


def range_cache_ttl(base_ttl: float, range_key: str) -> float:
    if range_key == "all":
        return max(base_ttl, LONG_RANGE_CACHE_TTL_SECONDS)
    if range_key == "30d":
        return max(base_ttl, MID_RANGE_CACHE_TTL_SECONDS)
    return base_ttl


def warm_default_caches() -> None:
    warm_session_snapshots()

    for project in PROJECTS:
        project_slug = project["slug"]
        cached_response(
            "project_detail",
            ttl_seconds=PROJECT_DETAIL_CACHE_TTL_SECONDS,
            builder=lambda project_slug=project_slug: build_project_detail(
                project_slug=project_slug,
                window_hours=24,
                bucket_minutes=DEFAULT_PROJECT_DETAIL_BUCKET_MINUTES,
                include_deep=False,
            ),
            project_slug=project_slug,
            window_hours=24,
            bucket_minutes=DEFAULT_PROJECT_DETAIL_BUCKET_MINUTES,
            include_deep=False,
        )


async def notification_worker(app: FastAPI) -> None:
    shutdown_event = get_shutdown_event(app)
    while not shutdown_event.is_set():
        wait_seconds = NOTIFICATION_LOOP_SECONDS
        try:
            result = await asyncio.to_thread(
                process_notification_batch,
                NOTIFICATION_BATCH_LIMIT,
            )
            app.state.notification_loop_state = result
            if result.get("mode") in {"disabled", "provider_not_configured", "persistence_disabled"}:
                wait_seconds = max(NOTIFICATION_LOOP_SECONDS, 15.0)
        except Exception as exc:
            app.state.notification_loop_state = {
                "mode": "error",
                "checked": 0,
                "delivered": 0,
                "suppressed": 0,
                "errors": 1,
                "last_run_at": iso_now(),
                "message": str(exc),
            }
            wait_seconds = max(NOTIFICATION_LOOP_SECONDS, 15.0)

        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=wait_seconds)
            break
        except asyncio.TimeoutError:
            continue


def require_admin_api_key(
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
) -> None:
    if not admin_api_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Traffic admin API key is not configured",
        )
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin key",
        )


def sse_payload(data: dict) -> str:
    return f"data: {json.dumps(data, separators=(',', ':'))}\n\n"


def stream_json_response(
    *,
    request: Request,
    builder: Callable[[], dict],
    poll_seconds: float,
    heartbeat_seconds: int,
) -> StreamingResponse:
    async def event_stream():
        last_signature = ""
        last_heartbeat = monotonic()
        shutdown_event = get_shutdown_event(request.app)
        request.app.state.active_streams = get_active_streams(request.app) + 1

        try:
            while True:
                if shutdown_event.is_set():
                    break
                if await request.is_disconnected():
                    break

                payload = builder()
                signature = json.dumps(payload, sort_keys=True, separators=(",", ":"))

                if signature != last_signature:
                    last_signature = signature
                    last_heartbeat = monotonic()
                    yield sse_payload(payload)
                elif monotonic() - last_heartbeat >= heartbeat_seconds:
                    last_heartbeat = monotonic()
                    yield ": keep-alive\n\n"

                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=poll_seconds)
                    break
                except asyncio.TimeoutError:
                    continue
        finally:
            request.app.state.active_streams = max(0, get_active_streams(request.app) - 1)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/healthz")
def healthz() -> dict[str, str | bool | int]:
    return {
        "ok": True,
        "service": "traffic-api",
        "version": app.version,
        "shutdown_requested": get_shutdown_event(app).is_set(),
        "active_streams": get_active_streams(app),
        "generated_at": iso_now(),
    }


@app.get("/api/admin/notifications/dashboard")
def api_admin_notifications_dashboard(
    request: Request,
    _: None = Depends(require_admin_api_key),
) -> dict:
    return build_notification_dashboard(loop_state=get_notification_loop_state(request.app))


@app.put("/api/admin/notifications/settings")
def api_admin_notification_settings(
    payload: dict = Body(...),
    _: None = Depends(require_admin_api_key),
) -> dict:
    settings = update_notification_settings(payload)
    return {
        "ok": True,
        "generated_at": iso_now(),
        "settings": settings,
    }


@app.post("/api/admin/notifications/mutes")
def api_admin_notification_mutes(
    payload: dict = Body(...),
    _: None = Depends(require_admin_api_key),
) -> dict:
    try:
        mute = create_notification_mute(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "generated_at": iso_now(),
        "mute": mute,
    }


@app.get("/api/admin/visibility-rules")
def api_admin_visibility_rules(
    _: None = Depends(require_admin_api_key),
) -> dict:
    return {
        "ok": True,
        "generated_at": iso_now(),
        "rules": list_visibility_rules(),
    }


@app.post("/api/admin/visibility-rules")
def api_admin_visibility_rules_create(
    payload: dict = Body(...),
    _: None = Depends(require_admin_api_key),
) -> dict:
    try:
        rule = create_visibility_rule(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    clear_session_snapshot_cache()
    clear_response_cache()
    return {
        "ok": True,
        "generated_at": iso_now(),
        "rule": rule,
    }


@app.post("/api/admin/notifications/operators")
def api_admin_notification_operators(
    payload: dict = Body(...),
    _: None = Depends(require_admin_api_key),
) -> dict:
    try:
        operator = create_operator_identity(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "generated_at": iso_now(),
        "operator": operator,
    }


@app.delete("/api/admin/notifications/mutes/{mute_id}")
def api_admin_notification_mute_delete(
    mute_id: int,
    _: None = Depends(require_admin_api_key),
) -> dict:
    delete_notification_mute(mute_id)
    return {
        "ok": True,
        "generated_at": iso_now(),
    }


@app.delete("/api/admin/visibility-rules/{rule_id}")
def api_admin_visibility_rule_delete(
    rule_id: int,
    _: None = Depends(require_admin_api_key),
) -> dict:
    delete_visibility_rule(rule_id)
    clear_session_snapshot_cache()
    clear_response_cache()
    return {
        "ok": True,
        "generated_at": iso_now(),
    }


@app.delete("/api/admin/notifications/operators/{operator_id}")
def api_admin_notification_operator_delete(
    operator_id: int,
    _: None = Depends(require_admin_api_key),
) -> dict:
    delete_operator_identity(operator_id)
    return {
        "ok": True,
        "generated_at": iso_now(),
    }


@app.post("/api/admin/notifications/test")
def api_admin_notification_test(
    _: None = Depends(require_admin_api_key),
) -> dict:
    try:
        result = send_test_notification()
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "generated_at": iso_now(),
        "result": result,
    }


@app.post("/api/admin/web-push/subscriptions")
def api_admin_web_push_subscription_create(
    payload: dict = Body(...),
    _: None = Depends(require_admin_api_key),
) -> dict:
    try:
        subscription = register_web_push_subscription(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "generated_at": iso_now(),
        "subscription": subscription,
    }


@app.delete("/api/admin/web-push/subscriptions/{subscription_id}")
def api_admin_web_push_subscription_delete(
    subscription_id: int,
    _: None = Depends(require_admin_api_key),
) -> dict:
    delete_web_push_subscription(subscription_id)
    return {
        "ok": True,
        "generated_at": iso_now(),
    }


@app.get("/api/overview")
def api_overview(
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
) -> dict:
    payload = cached_response(
        "overview",
        ttl_seconds=range_cache_ttl(OVERVIEW_CACHE_TTL_SECONDS, range_key),
        builder=lambda: build_overview(range_key=range_key),
        range_key=range_key,
    )

    return {
        "ok": payload["ok"],
        "generated_at": payload["generated_at"],
        "range_key": payload["range_key"],
        "range_label": payload["range_label"],
        "window_hours": payload["window_hours"],
        "window": payload["window"],
        "coverage_mode": payload["coverage_mode"],
        "coverage_started_at": payload["coverage_started_at"],
        "coverage_started_alberta": payload["coverage_started_alberta"],
        "note": payload["note"],
        "totals": payload["totals"],
        "projects": payload["projects"],
        "alerts": payload["alerts"],
        "notes": payload["notes"],
    }

@app.get("/api/summary")
def api_summary(
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
) -> dict:
    return api_overview(range_key=range_key)

@app.get("/api/projects")
def api_projects(
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
) -> list[dict]:
    return cached_response(
        "overview",
        ttl_seconds=range_cache_ttl(OVERVIEW_CACHE_TTL_SECONDS, range_key),
        builder=lambda: build_overview(range_key=range_key),
        range_key=range_key,
    )["projects"]


@app.get("/api/projects/{project_slug}")
def api_project_detail(
    project_slug: str,
    window_hours: int = Query(24, ge=1, le=168),
    bucket_minutes: int = Query(30, ge=1, le=120),
    include_deep: bool = Query(True),
) -> dict:
    if not any(project["slug"] == project_slug for project in PROJECTS):
        raise HTTPException(status_code=404, detail="Unknown project")

    return cached_response(
        "project_detail",
        ttl_seconds=PROJECT_DETAIL_CACHE_TTL_SECONDS,
        builder=lambda: build_project_detail(
            project_slug=project_slug,
            window_hours=window_hours,
            bucket_minutes=bucket_minutes,
            include_deep=include_deep,
        ),
        project_slug=project_slug,
        window_hours=window_hours,
        bucket_minutes=bucket_minutes,
        include_deep=include_deep,
    )


@app.get("/api/projects/{project_slug}/graph")
def api_project_graph(
    project_slug: str,
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
) -> dict:
    if not any(project["slug"] == project_slug for project in PROJECTS):
        raise HTTPException(status_code=404, detail="Unknown project")

    return cached_response(
        "project_graph",
        ttl_seconds=range_cache_ttl(SERIES_CACHE_TTL_SECONDS, range_key),
        builder=lambda: build_project_graph(
            project_slug=project_slug,
            range_key=range_key,
        ),
        project_slug=project_slug,
        range_key=range_key,
    )


@app.get("/api/projects/{project_slug}/live-feed")
def api_project_live_feed(
    project_slug: str,
    window_hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=100),
) -> dict:
    if not any(project["slug"] == project_slug for project in PROJECTS):
        raise HTTPException(status_code=404, detail="Unknown project")

    return cached_response(
        "project_live_feed",
        ttl_seconds=LIVE_VISITORS_CACHE_TTL_SECONDS,
        builder=lambda: build_project_live_feed(
            project_slug=project_slug,
            window_hours=window_hours,
            limit=limit,
        ),
        project_slug=project_slug,
        window_hours=window_hours,
        limit=limit,
    )


@app.get("/api/projects/{project_slug}/live-feed/stream")
def api_project_live_feed_stream(
    request: Request,
    project_slug: str,
    window_hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=100),
    poll_seconds: float = Query(1.5, ge=0.5, le=10.0),
    heartbeat_seconds: int = Query(20, ge=5, le=60),
) -> StreamingResponse:
    if not any(project["slug"] == project_slug for project in PROJECTS):
        raise HTTPException(status_code=404, detail="Unknown project")

    return stream_json_response(
        request=request,
        builder=lambda: cached_response(
            "project_live_feed",
            ttl_seconds=LIVE_VISITORS_CACHE_TTL_SECONDS,
            builder=lambda: build_project_live_feed(
                project_slug=project_slug,
                window_hours=window_hours,
                limit=limit,
            ),
            project_slug=project_slug,
            window_hours=window_hours,
            limit=limit,
        ),
        poll_seconds=poll_seconds,
        heartbeat_seconds=heartbeat_seconds,
    )


@app.get("/api/hosts")
def api_hosts() -> list[dict]:
    return cached_response(
        "overview",
        ttl_seconds=OVERVIEW_CACHE_TTL_SECONDS,
        builder=build_overview,
        range_key="24h",
    )["hosts"]


@app.get("/api/sessions")
def api_sessions() -> list[dict]:
    return cached_response(
        "overview",
        ttl_seconds=OVERVIEW_CACHE_TTL_SECONDS,
        builder=build_overview,
        range_key="24h",
    )["recent_sessions"]


@app.get("/api/paths")
def api_paths() -> list[dict]:
    return cached_response(
        "overview",
        ttl_seconds=OVERVIEW_CACHE_TTL_SECONDS,
        builder=build_overview,
        range_key="24h",
    )["top_pages"]


@app.get("/api/geo")
def api_geo() -> dict:
    return cached_response(
        "overview",
        ttl_seconds=OVERVIEW_CACHE_TTL_SECONDS,
        builder=build_overview,
        range_key="24h",
    )["geo"]


@app.get("/api/threats")
def api_threats() -> dict:
    return cached_response(
        "overview",
        ttl_seconds=OVERVIEW_CACHE_TTL_SECONDS,
        builder=build_overview,
        range_key="24h",
    )["suspicious"]


@app.get("/api/live-visitors")
def api_live_visitors(
    limit: int = Query(25, ge=1, le=100),
    history_limit: int = Query(250, ge=0, le=5000),
    window_hours: int = Query(24, ge=1, le=168),
) -> dict:
    return cached_response(
        "live_visitors",
        ttl_seconds=LIVE_VISITORS_CACHE_TTL_SECONDS,
        builder=lambda: build_live_visitors(
            limit=limit,
            history_limit=history_limit,
            window_hours=window_hours,
        ),
        limit=limit,
        history_limit=history_limit,
        window_hours=window_hours,
    )


@app.get("/api/live-visitors/stream")
def api_live_visitors_stream(
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    history_limit: int = Query(250, ge=0, le=5000),
    window_hours: int = Query(24, ge=1, le=168),
    poll_seconds: float = Query(5.0, ge=1.0, le=15.0),
    heartbeat_seconds: int = Query(20, ge=5, le=60),
) -> StreamingResponse:
    return stream_json_response(
        request=request,
        builder=lambda: cached_response(
            "live_visitors",
            ttl_seconds=LIVE_VISITORS_CACHE_TTL_SECONDS,
            builder=lambda: build_live_visitors(
                limit=limit,
                history_limit=history_limit,
                window_hours=window_hours,
            ),
            limit=limit,
            history_limit=history_limit,
            window_hours=window_hours,
        ),
        poll_seconds=poll_seconds,
        heartbeat_seconds=heartbeat_seconds,
    )


@app.get("/api/visitors/{visitor_id}")
def api_visitor_profile(
    visitor_id: str,
    range_key: str = Query("all", pattern="^(24h|7d|30d|all)$"),
) -> dict:
    return cached_response(
        "visitor_profile",
        ttl_seconds=range_cache_ttl(VISITOR_PROFILE_CACHE_TTL_SECONDS, range_key),
        builder=lambda: build_visitor_profile(
            visitor_id=visitor_id,
            range_key=range_key,
        ),
        visitor_id=visitor_id,
        range_key=range_key,
    )


@app.get("/api/visitors/{visitor_id}/stream")
async def api_visitor_profile_stream(
    request: Request,
    visitor_id: str,
    range_key: str = Query("all", pattern="^(24h|7d|30d|all)$"),
    poll_seconds: float = Query(1.5, ge=0.5, le=10.0),
    heartbeat_seconds: int = Query(20, ge=5, le=60),
) -> StreamingResponse:
    initial_profile = cached_response(
        "visitor_profile",
        ttl_seconds=range_cache_ttl(VISITOR_PROFILE_CACHE_TTL_SECONDS, range_key),
        builder=lambda: build_visitor_profile(
            visitor_id=visitor_id,
            range_key=range_key,
        ),
        visitor_id=visitor_id,
        range_key=range_key,
    )
    if not initial_profile.get("ok"):
        raise HTTPException(status_code=404, detail="Unknown visitor")

    return stream_json_response(
        request=request,
        builder=lambda: cached_response(
            "visitor_profile",
            ttl_seconds=range_cache_ttl(VISITOR_PROFILE_CACHE_TTL_SECONDS, range_key),
            builder=lambda: build_visitor_profile(
                visitor_id=visitor_id,
                range_key=range_key,
            ),
            visitor_id=visitor_id,
            range_key=range_key,
        ),
        poll_seconds=poll_seconds,
        heartbeat_seconds=heartbeat_seconds,
    )


@app.get("/api/project-human-series")
def api_project_human_series(
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
    bucket_minutes: int | None = Query(None, ge=1, le=1440),
) -> dict:
    return cached_response(
        "project_human_series",
        ttl_seconds=range_cache_ttl(SERIES_CACHE_TTL_SECONDS, range_key),
        builder=lambda: build_project_human_series(
            range_key=range_key,
            bucket_minutes_override=bucket_minutes,
        ),
        range_key=range_key,
        bucket_minutes=bucket_minutes,
    )


@app.get("/api/visits/history")
def api_visits_history(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    range_key: str = Query("all", pattern="^(24h|7d|30d|all)$"),
    classification: str | None = Query(None),
    project: str | None = Query(None),
    projects: str | None = Query(None),
) -> dict:
    selected_projects: list[str] | None = None
    if projects is not None:
        selected_projects = [value.strip() for value in projects.split(",") if value.strip()]
    elif project:
        selected_projects = [project]

    return cached_response(
        "visits_history",
        ttl_seconds=range_cache_ttl(VISITS_HISTORY_CACHE_TTL_SECONDS, range_key),
        builder=lambda: build_visits_history(
            limit=limit,
            offset=offset,
            range_key=range_key,
            classification=classification,
            project_slugs=selected_projects,
        ),
        limit=limit,
        offset=offset,
        range_key=range_key,
        classification=classification,
        projects=",".join(selected_projects or ()),
    )
    

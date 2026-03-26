from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager
import json
import signal
from time import monotonic
import threading

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from app.services.traffic.config import (
    ADMIN_API_KEY,
    NOTIFICATION_BATCH_LIMIT,
    NOTIFICATION_LOOP_SECONDS,
    PROJECTS,
)
from app.services.traffic.notifications import (
    admin_api_configured,
    build_notification_dashboard,
    create_notification_mute,
    delete_notification_mute,
    process_notification_batch,
    send_test_notification,
    update_notification_settings,
)
from app.services.traffic.parse import iso_now
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

    try:
        yield
    finally:
        shutdown_event.set()
        if notification_task is not None:
            try:
                await asyncio.wait_for(notification_task, timeout=NOTIFICATION_LOOP_SECONDS + 5)
            except asyncio.TimeoutError:
                notification_task.cancel()
        if threading.current_thread() is threading.main_thread():
            for signum, previous in previous_handlers.items():
                signal.signal(signum, previous)


app = FastAPI(title="Traffic API", version="0.3.0", lifespan=lifespan)

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


async def notification_worker(app: FastAPI) -> None:
    shutdown_event = get_shutdown_event(app)
    while not shutdown_event.is_set():
        try:
            result = await asyncio.to_thread(
                process_notification_batch,
                NOTIFICATION_BATCH_LIMIT,
            )
            app.state.notification_loop_state = result
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

        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=NOTIFICATION_LOOP_SECONDS)
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


@app.get("/api/overview")
def api_overview(
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
) -> dict:
    return build_overview(range_key=range_key)


@app.get("/api/summary")
def api_summary(
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
) -> dict:
    return build_overview(range_key=range_key)


@app.get("/api/projects")
def api_projects(
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
) -> list[dict]:
    return build_overview(range_key=range_key)["projects"]


@app.get("/api/projects/{project_slug}")
def api_project_detail(
    project_slug: str,
    window_hours: int = Query(24, ge=1, le=168),
    bucket_minutes: int = Query(30, ge=1, le=120),
) -> dict:
    if not any(project["slug"] == project_slug for project in PROJECTS):
        raise HTTPException(status_code=404, detail="Unknown project")

    return build_project_detail(
        project_slug=project_slug,
        window_hours=window_hours,
        bucket_minutes=bucket_minutes,
    )


@app.get("/api/projects/{project_slug}/graph")
def api_project_graph(
    project_slug: str,
    range_key: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
) -> dict:
    if not any(project["slug"] == project_slug for project in PROJECTS):
        raise HTTPException(status_code=404, detail="Unknown project")

    return build_project_graph(
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

    return build_project_live_feed(
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
        builder=lambda: build_project_live_feed(
            project_slug=project_slug,
            window_hours=window_hours,
            limit=limit,
        ),
        poll_seconds=poll_seconds,
        heartbeat_seconds=heartbeat_seconds,
    )


@app.get("/api/hosts")
def api_hosts() -> list[dict]:
    return build_overview()["hosts"]


@app.get("/api/sessions")
def api_sessions() -> list[dict]:
    return build_overview()["recent_sessions"]


@app.get("/api/paths")
def api_paths() -> list[dict]:
    return build_overview()["top_pages"]


@app.get("/api/geo")
def api_geo() -> dict:
    return build_overview()["geo"]


@app.get("/api/threats")
def api_threats() -> dict:
    return build_overview()["suspicious"]


@app.get("/api/live-visitors")
def api_live_visitors(
    limit: int = Query(25, ge=1, le=100),
    history_limit: int = Query(250, ge=0, le=5000),
    window_hours: int = Query(24, ge=1, le=168),
) -> dict:
    return build_live_visitors(
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
    poll_seconds: float = Query(1.5, ge=0.5, le=10.0),
    heartbeat_seconds: int = Query(20, ge=5, le=60),
) -> StreamingResponse:
    return stream_json_response(
        request=request,
        builder=lambda: build_live_visitors(
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
    return build_visitor_profile(
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
    initial_profile = build_visitor_profile(
        visitor_id=visitor_id,
        range_key=range_key,
    )
    if not initial_profile.get("ok"):
        raise HTTPException(status_code=404, detail="Unknown visitor")

    return stream_json_response(
        request=request,
        builder=lambda: build_visitor_profile(
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
    return build_project_human_series(
        range_key=range_key,
        bucket_minutes_override=bucket_minutes,
    )


@app.get("/api/visits/history")
def api_visits_history(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    range_key: str = Query("all", pattern="^(24h|7d|30d|all)$"),
    classification: str | None = Query(None),
    project: str | None = Query(None),
) -> dict:
    return build_visits_history(
        limit=limit,
        offset=offset,
        range_key=range_key,
        classification=classification,
        project=project,
    )

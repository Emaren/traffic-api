from __future__ import annotations

import asyncio
from collections.abc import Callable
import json
from time import monotonic

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from app.services.traffic.config import PROJECTS
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

app = FastAPI(title="Traffic API", version="0.3.0")

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

        while True:
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

            await asyncio.sleep(poll_seconds)

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
def healthz() -> dict[str, str | bool]:
    return {
        "ok": True,
        "service": "traffic-api",
        "version": app.version,
        "generated_at": iso_now(),
    }


@app.get("/api/overview")
def api_overview() -> dict:
    return build_overview()


@app.get("/api/summary")
def api_summary() -> dict:
    return build_overview()


@app.get("/api/projects")
def api_projects() -> list[dict]:
    return build_overview()["projects"]


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
    window_hours: int = Query(24, ge=1, le=168),
    bucket_minutes: int = Query(30, ge=1, le=120),
) -> dict:
    return build_project_human_series(
        window_hours=window_hours,
        bucket_minutes=bucket_minutes,
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

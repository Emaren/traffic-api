from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app.services.traffic.config import PROJECTS
from app.services.traffic.parse import iso_now
from app.services.traffic_core import (
    build_live_visitors,
    build_overview,
    build_project_detail,
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


@app.get("/api/visitors/{visitor_id}")
def api_visitor_profile(
    visitor_id: str,
    window_hours: int = Query(24, ge=1, le=168),
) -> dict:
    return build_visitor_profile(
        visitor_id=visitor_id,
        window_hours=window_hours,
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
    window_hours: int = Query(24, ge=1, le=168),
    classification: str | None = Query(None),
    project: str | None = Query(None),
) -> dict:
    return build_visits_history(
        limit=limit,
        offset=offset,
        window_hours=window_hours,
        classification=classification,
        project=project,
    )

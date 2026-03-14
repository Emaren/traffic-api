from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI

from app.services.traffic_core import build_overview

app = FastAPI(title="Traffic API", version="0.2.0")


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "traffic-api",
        "version": "0.2.0",
        "generated_at": iso_now(),
    }


@app.get("/api/summary")
async def summary() -> dict[str, Any]:
    return build_overview()


@app.get("/api/overview")
async def overview() -> dict[str, Any]:
    return build_overview()


@app.get("/api/projects")
async def projects() -> dict[str, Any]:
    overview_payload = build_overview()
    return {
        "ok": True,
        "generated_at": overview_payload["generated_at"],
        "projects": overview_payload["projects"],
    }


@app.get("/api/hosts")
async def hosts() -> dict[str, Any]:
    overview_payload = build_overview()
    return {
        "ok": True,
        "generated_at": overview_payload["generated_at"],
        "hosts": overview_payload["hosts"],
    }


@app.get("/api/sessions")
async def sessions() -> dict[str, Any]:
    overview_payload = build_overview()
    return {
        "ok": True,
        "generated_at": overview_payload["generated_at"],
        "sessions": overview_payload["recent_sessions"],
    }


@app.get("/api/paths")
async def paths() -> dict[str, Any]:
    overview_payload = build_overview()
    return {
        "ok": True,
        "generated_at": overview_payload["generated_at"],
        "paths": overview_payload["top_pages"],
    }


@app.get("/api/geo")
async def geo() -> dict[str, Any]:
    overview_payload = build_overview()
    return {
        "ok": True,
        "generated_at": overview_payload["generated_at"],
        "countries": overview_payload["geo"]["countries"],
        "areas": overview_payload["geo"]["areas"],
        "cities": overview_payload["geo"]["cities"],
    }


@app.get("/api/threats")
async def threats() -> dict[str, Any]:
    overview_payload = build_overview()

    top_hosts = sorted(
        (
            {
                "host": row["host"],
                "count": row["suspicious_requests"],
            }
            for row in overview_payload["hosts"]
            if row["suspicious_requests"] > 0
        ),
        key=lambda row: row["count"],
        reverse=True,
    )

    suspicious_sessions = sum(
        1 for session in overview_payload["recent_sessions"] if session["suspicious_score"] >= 40
    )

    return {
        "ok": True,
        "generated_at": overview_payload["generated_at"],
        "summary": {
            "suspicious_requests": overview_payload["totals"]["suspicious"],
            "suspicious_sessions": suspicious_sessions,
            "repeat_bad_ips": len(overview_payload["suspicious"]["top_ips"]),
        },
        "top_paths": overview_payload["suspicious"]["top_paths"],
        "top_ips": overview_payload["suspicious"]["top_ips"],
        "top_hosts": top_hosts,
    }
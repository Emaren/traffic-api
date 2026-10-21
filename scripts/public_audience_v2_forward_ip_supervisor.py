#!/usr/bin/env python3
"""Operator-only bounded PRIVATE forward IP-shadow catch-up.

Runs the already-audited single-step command in isolated child processes.
No systemd installation, source writes, public-day publication or retry loops.
A child failure/timeout stops the sequence; committed batches remain durable.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from scripts import public_audience_v2_guarded_resume as guard

MAX_STEPS = 16
MAX_ROWS = 3000
MAX_WALL_SECONDS = 300
PROJECT = "traffic-project-daily-rollups-aoe2hdbets"
PRIVATE_TIMER = "traffic-v2-forward-ledger-aoe2hdbets.timer"
LEGACY_TIMER = "traffic-public-audience-aoe2hdbets.timer"


def require(ok: bool, message: str) -> None:
    guard.require(ok, message)


def check_timer_state() -> None:
    guard.require_worker_priority()
    require(
        guard.unit_state(PRIVATE_TIMER, "ActiveState") == "active"
        and guard.unit_state(PRIVATE_TIMER, "UnitFileState") == "enabled",
        "automatic PRIVATE source evidence collector must remain enabled",
    )
    require(
        guard.unit_state(LEGACY_TIMER, "ActiveState") == "inactive"
        and guard.unit_state(LEGACY_TIMER, "UnitFileState") == "disabled",
        "legacy public audience generator unexpectedly enabled",
    )


def check_receipt(initial: dict[str, Any], after: dict[str, Any], *,
                  max_rows: int, previous_cursor: int | None) -> dict[str, int]:
    require(initial.get("result") == "READY_PRIVATE_PASS1"
            and initial.get("forward_phase") == "LIVE",
            "forward evidence ledger must be LIVE")
    require(initial.get("publication_authorized") is False
            and initial.get("daily_classification_ready") is False
            and initial.get("private_ip_shadow_writes_only") is True,
            "unsafe initial private-only receipt")

    require(after.get("result") == "PRIVATE_PASS1_STEP"
            and after.get("publication_authorized") is False
            and after.get("daily_classification_ready") is False
            and after.get("private_ip_shadow_writes_only") is True,
            "unsafe step receipt: public publication must remain forbidden")
    for field in ("step_input_events", "total_input_events_processed",
                  "last_source_rowid", "remaining_retained_events"):
        require(type(after.get(field)) is int and after[field] >= 0,
                f"invalid private shadow receipt: {field}")
    count = after["step_input_events"]
    require(0 <= count <= max_rows, "out-of-bounds private IP batch")
    before = initial.get("shadow_processed_events")
    require(type(before) is int and before >= 0,
            "initial processed cursor invalid")
    require(after["total_input_events_processed"] == before + count,
            "private shadow processed cursor mismatch")
    require(after["remaining_retained_events"] >= 0,
            "negative private retained backlog")
    if previous_cursor is not None:
        require(after["last_source_rowid"] > previous_cursor if count else
                after["last_source_rowid"] == previous_cursor,
                "private rowid cursor did not advance consistently")
    return {"count": count, "processed": after["total_input_events_processed"],
            "cursor": after["last_source_rowid"],
            "remaining": after["remaining_retained_events"]}


def run_child(cmd: list[str], *, workdir: Path, timeout_seconds: int) -> dict:
    try:
        result = subprocess.run(
            cmd, cwd=workdir, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("STOP: private IP child exceeded time bound") from exc
    require(result.returncode == 0,
            "private IP child SAFE STOP; exit="
            + str(result.returncode) + " "
            + (result.stderr.strip()[:300] or "no diagnostic"))
    try:
        payload = json.loads(result.stdout.strip())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("STOP: invalid private IP child JSON receipt") from exc
    require(isinstance(payload, dict), "private IP receipt not JSON object")
    return payload


def supervise(args: argparse.Namespace,
              child: Callable[..., dict] = run_child) -> dict[str, Any]:
    repo = Path(__file__).resolve().parents[1]
    require(1 <= args.max_steps <= MAX_STEPS, "invalid max_steps")
    require(1 <= args.max_rows <= MAX_ROWS, "invalid max_rows")
    require(45 <= args.wall_seconds <= MAX_WALL_SECONDS,
            "invalid wall budget")
    require(5 <= args.step_timeout <= 40
            and args.wall_seconds >= args.step_timeout + 10,
            "invalid individual step timeout")
    require(len(args.require_sha) == 40
            and all(ch in "0123456789abcdef" for ch in args.require_sha),
            "operator requires exact pinned Git SHA")
    require(guard.cmd_output("git", "rev-parse", "HEAD", cwd=repo)
            == args.require_sha, "source release moved")
    require(not guard.cmd_output("git", "status", "--porcelain", cwd=repo),
            "Traffic checkout is dirty")
    check_timer_state()
    guard.resource_headroom(args.shadow, args.min_data_gib, args.min_root_gib)

    base = [
        sys.executable, "-m", "scripts.public_audience_v2_forward_ip_shadow",
        "--source", str(args.source),
        "--checkpoint", str(args.checkpoint),
        "--ledger", str(args.ledger),
        "--shadow", str(args.shadow),
    ]
    first = child(base, workdir=repo, timeout_seconds=args.step_timeout)
    require(first.get("result") == "READY_PRIVATE_PASS1"
            and first.get("forward_phase") == "LIVE",
            "forward ledger not LIVE; do not advance private shadow")
    require(first.get("publication_authorized") is False
            and first.get("daily_classification_ready") is False
            and first.get("private_ip_shadow_writes_only") is True,
            "readonly preflight did not deny public writes")

    initial = int(first["shadow_processed_events"])
    current = dict(first)
    deadline = time.monotonic() + args.wall_seconds
    results = []
    last_cursor: int | None = None
    stop_reason = "max_steps"
    for _ in range(args.max_steps):
        if time.monotonic() + args.step_timeout + 3 >= deadline:
            stop_reason = "wall_budget"
            break
        # Every child independently takes the private canary flock; never
        # hold the flock here while the child is working.
        check_timer_state()
        require(guard.worker_idle(), "project rollup worker has priority")
        guard.resource_headroom(args.shadow, args.min_data_gib,
                                args.min_root_gib)
        next_step = child(
            [*base, "--max-rows", str(args.max_rows),
             "--advance", "--approve-private-write"],
            workdir=repo, timeout_seconds=args.step_timeout,
        )
        report = check_receipt(
            current, next_step, max_rows=args.max_rows,
            previous_cursor=last_cursor,
        )
        results.append(report)
        print(json.dumps({
            "event": "PRIVATE_SHADOW_STEP",
            "step": len(results),
            "rows": report["count"],
            "processed": report["processed"],
            "remaining": report["remaining"],
            "publication_authorized": False,
        }, sort_keys=True), flush=True)
        last_cursor = report["cursor"]
        current = {
            "result": "READY_PRIVATE_PASS1",
            "forward_phase": "LIVE",
            "shadow_processed_events": report["processed"],
            "publication_authorized": False,
            "daily_classification_ready": False,
            "private_ip_shadow_writes_only": True,
        }
        if report["count"] == 0:
            stop_reason = "source_caught_up"
            break
    final = int(current["shadow_processed_events"])
    return {
        "result": "PRIVATE_IP_SHADOW_BOUNDED_SUPERVISOR",
        "reason": stop_reason,
        "steps": len(results),
        "processed_before": initial,
        "processed_after": final,
        "events_added": final - initial,
        "remaining_at_last_step": (
            results[-1]["remaining"] if results else
            first["remaining_retained_events"]
        ),
        "no_publication": True,
        "publication_authorized": False,
        "new_systemd_units_enabled": False,
        "utc_days_certified": [],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--checkpoint", type=Path, required=True)
    p.add_argument("--ledger", type=Path, required=True)
    p.add_argument("--shadow", type=Path, required=True)
    p.add_argument("--require-sha", required=True)
    p.add_argument("--max-steps", type=int, default=8)
    p.add_argument("--max-rows", type=int, default=3000)
    p.add_argument("--wall-seconds", type=int, default=120)
    p.add_argument("--step-timeout", type=int, default=25)
    p.add_argument("--min-data-gib", type=int, default=8)
    p.add_argument("--min-root-gib", type=int, default=4)
    args = p.parse_args()
    try:
        require(1 <= args.min_data_gib <= 100
                and 1 <= args.min_root_gib <= 100,
                "invalid disk reserve")
        print(json.dumps(supervise(args), sort_keys=True), flush=True)
        return 0
    except (ValueError, RuntimeError, OSError, sqlite3.Error,
            subprocess.SubprocessError, KeyError, TypeError) as exc:
        print("SAFE STOP:", str(exc), file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

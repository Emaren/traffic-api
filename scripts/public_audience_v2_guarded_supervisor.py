#!/usr/bin/env python3
"""Operator-started, bounded foreground supervisor for private Traffic V2 pass two.

Waits for the independent project rollup worker, resumes the existing
guarded runner, verifies private receipts, and stops on *any* abnormal result.
Never schedules itself, writes public rows, or replays pass one.
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from scripts import public_audience_v2_guarded_resume as replay

MIN_AVAILABLE_KIB = 1_048_576
AS_LIMIT_BYTES = 786_432 * 1024
EXPECTED_FIRST_CURSOR = 4_471_344


def require_memory() -> None:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            replay.require(
                int(line.split()[1]) >= MIN_AVAILABLE_KIB,
                "less than 1 GiB system memory available",
            )
            return
    raise RuntimeError("STOP: unable to read MemAvailable")


def read_window_receipt(path: Path, *, source_sha: str) -> dict:
    replay.require(path.is_file() and not path.is_symlink(),
                   "window receipt missing or symlink")
    replay.require(path.stat().st_mode & 0o777 == 0o600,
                   "window receipt must remain private 0600")
    events = [json.loads(line) for line in path.read_text().splitlines()]
    replay.require(len(events) >= 2 and events[0].get("event") == "START",
                   "missing window START receipt")
    replay.require(events[0].get("source_sha") == source_sha,
                   "window receipt source drift")
    replay.require(events[-1].get("event") == "STOP",
                   "window ended without STOP receipt")
    replay.require(
        all(event.get("event") == "STEP" for event in events[1:-1]),
        "unexpected private window events",
    )
    steps = events[1:-1]
    replay.require(
        len(steps) == int(events[-1].get("steps", -1)),
        "window step count/receipt mismatch",
    )
    last = events[-1]
    replay.require(last.get("publication_authorized") is False,
                   "unexpected publication authorization")
    replay.require(
        last.get("reason") in {
            "max_steps", "wall_budget", "project_worker_priority",
            "performance_soft_stop", "PASS2_COMPLETE",
        }, "unknown recovery stop reason",
    )
    return {
        "reason": last["reason"],
        "phase": last["phase"],
        "p2_raw": int(last["p2_raw"]),
        "steps": len(steps),
        "peak_rss_kib": max((e["peak_rss_kib"] for e in steps), default=0),
        "max_closed_session_events": max(
            (e["performance"]["max_closed_session_events"] for e in steps),
            default=0,
        ),
        "receipt": path.name,
    }


def wait_for_worker(state: Path, deadline: float, *, max_wait_seconds: int,
                    wait_seconds: int) -> bool:
    started = time.monotonic()
    while not replay.worker_idle():
        replay.require_worker_priority()
        replay.resource_headroom(state, 12, 6)
        require_memory()
        if (time.monotonic() - started >= max_wait_seconds
                or time.monotonic() + wait_seconds >= deadline):
            return False
        time.sleep(wait_seconds)
    return True


def run(args: argparse.Namespace) -> int:
    repo = Path(__file__).resolve().parents[1]
    state = args.state
    source = args.source.resolve(strict=True)
    replay.require(not state.is_symlink() and state.is_file(),
                   "existing private checkpoint required")
    replay.require(state.stat().st_mode & 0o777 == 0o600,
                   "private checkpoint must be mode 0600")
    replay.require(300 <= args.total_seconds <= 10_800,
                   "overall time budget outside guarded range")
    replay.require(60 <= args.window_seconds <= 1800,
                   "inner window time budget outside guarded range")
    replay.require(1 <= args.max_windows <= 24,
                   "window count outside guarded range")
    replay.require(5 <= args.worker_poll_seconds <= 60,
                   "worker poll interval outside guarded range")
    replay.require(30 <= args.worker_wait_seconds <= 900,
                   "worker wait budget outside guarded range")
    replay.require(
        replay.cmd_output("git", "rev-parse", "HEAD", cwd=repo) == args.require_sha,
        "unreviewed Traffic source SHA",
    )
    replay.require(
        not replay.cmd_output("git", "status", "--porcelain", cwd=repo),
        "dirty Traffic working tree",
    )
    replay.require_worker_priority()
    replay.resource_headroom(state, 12, 6)
    require_memory()
    info = replay.checkpoint_info(state)
    replay.verify_frozen(source, state, info)
    replay.require(
        EXPECTED_FIRST_CURSOR <= int(info["p2_raw"]) <= replay.FROZEN_ROWS,
        "unexpected current replay cursor",
    )
    initial = int(info["p2_raw"])
    print(json.dumps({
        "event": "SUPERVISOR_START", "at": datetime.now(timezone.utc).isoformat(),
        "p2_raw": initial, "source_sha": args.require_sha,
        "publication_authorized": False,
    }), flush=True)

    deadline = time.monotonic() + args.total_seconds
    last_cursor = initial
    windows = 0
    reason = "max_windows"

    while windows < args.max_windows:
        if time.monotonic() + args.window_seconds + 60 >= deadline:
            reason = "total_budget"
            break
        replay.require_worker_priority()
        replay.resource_headroom(state, 12, 6)
        require_memory()
        info = replay.checkpoint_info(state)
        replay.verify_frozen(source, state, info)
        replay.require(int(info["p2_raw"]) == last_cursor,
                       "unexpected concurrent cursor movement")
        if info["phase"] == "PASS2_COMPLETE":
            reason = "PASS2_COMPLETE"
            break

        if not wait_for_worker(
            state, deadline, max_wait_seconds=args.worker_wait_seconds,
            wait_seconds=args.worker_poll_seconds,
        ):
            reason = "worker_wait_limit"
            break

        before = {p.name for p in state.parent.glob("v2-pass2-guarded-*.jsonl")}
        command = [
            sys.executable, "-m", "scripts.public_audience_v2_guarded_resume",
            "--source", str(source), "--state", str(state),
            "--require-sha", args.require_sha,
            "--wall-seconds", str(args.window_seconds),
            "--max-steps", "240",
            "--rows-per-step", "20000",
            "--budget-seconds", "25",
            "--hard-seconds", "35",
            "--max-elapsed-seconds", "18",
            "--max-rss-kib", "327680",
            "--min-data-gib", "12",
            "--min-root-gib", "6",
        ]
        # The inner runner writes its own fsynced PRIVATE receipts. The outer
        # controller prints only a compact count, never private source events.
        proc = subprocess.Popen(
            command, cwd=repo, start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            _out, stderr = proc.communicate(timeout=args.window_seconds + 65)
        except subprocess.TimeoutExpired as exc:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise RuntimeError(
                "STOP: full replay subprocess group exceeded supervised deadline"
            ) from exc
        replay.require(proc.returncode == 0,
                       "inner runner failed; inspect private FAIL receipt")
        after = {
            p.name: p for p in state.parent.glob("v2-pass2-guarded-*.jsonl")
        }
        new = set(after) - before
        replay.require(len(new) == 1,
                       "expected exactly one new private runner receipt")
        report = read_window_receipt(after[new.pop()], source_sha=args.require_sha)
        now = replay.checkpoint_info(state)
        replay.verify_frozen(source, state, now)
        replay.require(
            int(now["p2_raw"]) == report["p2_raw"],
            "private receipt and checkpoint cursor disagree",
        )
        replay.require(report["p2_raw"] >= last_cursor,
                       "checkpoint cursor regressed")
        replay.require(
            report["p2_raw"] > last_cursor
            or report["reason"] in ("project_worker_priority", "PASS2_COMPLETE"),
            "no forward replay progress",
        )
        last_cursor = report["p2_raw"]
        windows += 1
        print(json.dumps({
            "event": "SUPERVISED_WINDOW", "window": windows, **report,
        }, sort_keys=True), flush=True)
        if report["reason"] == "performance_soft_stop":
            reason = "performance_soft_stop"
            break
        if report["reason"] == "PASS2_COMPLETE":
            reason = "PASS2_COMPLETE"
            break
        if report["reason"] not in (
            "max_steps", "wall_budget", "project_worker_priority",
        ):
            raise RuntimeError("STOP: invalid inner runner termination")

    final = replay.checkpoint_info(state)
    replay.verify_frozen(source, state, final)
    replay.require(int(final["p2_raw"]) == last_cursor,
                   "unexplained cursor change at supervisor exit")
    print(json.dumps({
        "event": "SUPERVISOR_STOP",
        "reason": reason, "windows": windows,
        "from_raw": initial, "p2_raw": int(final["p2_raw"]),
        "phase": final["phase"],
        "source_pass_digest_equal": (
            final["phase"] == "PASS2_COMPLETE"
            and final["p2_digest"] == replay.FROZEN_DIGEST
        ),
        "publication_authorized": False,
    }, sort_keys=True), flush=True)
    return 0 if reason in (
        "PASS2_COMPLETE", "total_budget", "max_windows",
    ) else 3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--require-sha", required=True)
    parser.add_argument("--total-seconds", type=int, default=7200)
    parser.add_argument("--window-seconds", type=int, default=900)
    parser.add_argument("--max-windows", type=int, default=12)
    parser.add_argument("--worker-poll-seconds", type=int, default=15)
    parser.add_argument("--worker-wait-seconds", type=int, default=600)
    opts = parser.parse_args()
    # OS hard *virtual address space* backstop inherited by all children.
    current_soft, current_hard = resource.getrlimit(resource.RLIMIT_AS)
    target_soft = min(AS_LIMIT_BYTES, current_soft) if current_soft >= 0 else AS_LIMIT_BYTES
    target_hard = min(AS_LIMIT_BYTES, current_hard) if current_hard >= 0 else AS_LIMIT_BYTES
    resource.setrlimit(resource.RLIMIT_AS, (target_soft, target_hard))
    try:
        return run(opts)
    except (RuntimeError, OSError, ValueError, KeyError,
            subprocess.SubprocessError) as exc:
        print("SAFE STOP:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

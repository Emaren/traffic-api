#!/usr/bin/env python3
"""Guarded, resumable PASS-TWO-only historical Traffic V2 operator runner.

Private checkpoint writes ONLY. Does not publish audience rollups or change timers.
Run as the authorized operator from the exact pinned Traffic repository release.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from shutil import disk_usage

from scripts import public_audience_v2_checkpoint as v2
from scripts import public_audience_v2_sessions as sessions

WORKER = "traffic-project-daily-rollups-aoe2hdbets"
LEGACY = "traffic-public-audience-aoe2hdbets"
FROZEN_ROWS = 21_618_093
FROZEN_ACCEPTED = 21_618_090
FROZEN_DIGEST = "6606f0277cf7c94249f73d4ffce83826068aa00fd78212014fa1422dc46c0f33"
GIB = 1024**3


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def cmd_output(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(
        args, cwd=cwd, text=True, stderr=subprocess.DEVNULL, timeout=10,
    ).strip()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError("STOP: " + reason)


def checkpoint_info(state: Path) -> dict[str, str]:
    with closing(sqlite3.connect(
        f"file:{state.resolve().as_posix()}?mode=ro", uri=True, timeout=2,
    )) as db:
        db.execute("PRAGMA query_only=ON")
        return dict(db.execute("SELECT key,value FROM metadata"))


def verify_frozen(raw: Path, state: Path, info: dict[str, str]) -> None:
    require(info["phase"] in ("PASS2_RUNNING", "PASS2_COMPLETE"),
            "frozen first pass / running second pass required")
    require(int(info["raw_scanned"]) == FROZEN_ROWS, "source raw row-count drift")
    require(int(info["accepted"]) == FROZEN_ACCEPTED, "source accepted row-count drift")
    require(info["p1_digest"] == FROZEN_DIGEST, "frozen source digest mismatch")
    require(int(info["watermark"]) == 44_247_247, "source watermark mismatch")
    require(info["start"] == "2026-05-22T00:00:00+00:00", "start epoch mismatch")
    require(info["end"] == "2026-10-20T00:00:00+00:00", "end epoch mismatch")
    require(51_344 <= int(info["p2_raw"]) <= FROZEN_ROWS, "unexpected replay cursor")
    sessions.verified_state(raw, state, info)
    if info["phase"] == "PASS2_COMPLETE":
        require(int(info["p2_raw"]) == FROZEN_ROWS, "final raw parity failure")
        require(int(info["p2_accepted"]) == FROZEN_ACCEPTED,
                "final accepted parity failure")
        require(info["p2_digest"] == FROZEN_DIGEST, "final digest parity failure")


def unit_state(unit: str, property_name: str) -> str:
    return cmd_output("systemctl", "show", unit, "-p",
                      property_name, "--value", "--no-pager")


def require_worker_priority() -> None:
    require(unit_state(WORKER + ".timer", "ActiveState") == "active",
            "independent 30-minute project timer inactive")
    require(unit_state(WORKER + ".timer", "UnitFileState") == "enabled",
            "independent 30-minute project timer disabled")
    require(unit_state(LEGACY + ".timer", "ActiveState") == "inactive",
            "failed legacy audience timer unexpectedly active")
    require(unit_state(LEGACY + ".timer", "UnitFileState") == "disabled",
            "failed legacy audience timer unexpectedly enabled")


def worker_idle() -> bool:
    return (unit_state(WORKER + ".service", "ActiveState") == "inactive"
            and unit_state(WORKER + ".service", "Result") == "success")


def resource_headroom(state: Path, min_data_gib: int, min_root_gib: int) -> None:
    require(disk_usage(state.parent).free > min_data_gib * GIB,
            "data volume reserve below threshold")
    require(disk_usage("/").free > min_root_gib * GIB,
            "root volume reserve below threshold")


def open_private_file(path: Path, flags: int) -> int:
    fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    mode = os.fstat(fd).st_mode
    require(stat.S_ISREG(mode), "lock/receipt path must be regular")
    require((mode & 0o077) == 0, "lock/receipt permissions must be private")
    return fd


def record(fd: int, entry: dict) -> None:
    payload = (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode()
    os.write(fd, payload)
    os.fsync(fd)
    print(json.dumps(entry, sort_keys=True), flush=True)


def run_one(raw: Path, state: Path, *, max_rows: int, budget_seconds: int,
            hard_seconds: int, metrics_path: Path, repo: Path) -> tuple[dict, float, int]:
    command = [
        "/usr/bin/time", "-f", "%e %M", "-o", str(metrics_path),
        "/usr/bin/timeout", "-k", "5s", f"{hard_seconds}s",
        "/usr/bin/nice", "-n", "15",
        sys.executable, "-m", "scripts.public_audience_v2_sessions",
        "advance", "--source", str(raw), "--state", str(state),
        "--max-rows", str(max_rows), "--budget-seconds", str(budget_seconds),
    ]
    result = subprocess.run(
        command, cwd=repo, text=True, capture_output=True,
        timeout=hard_seconds + 8, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"STOP: replay step exit={result.returncode}; "
                           "checkpoint must be inspected before retry")
    try:
        output = json.loads(result.stdout.strip())
        elapsed, rss = metrics_path.read_text().split()
        return output, float(elapsed), int(rss)
    except (ValueError, KeyError, OSError, TypeError) as exc:
        raise RuntimeError("STOP: invalid private replay step receipt") from exc


def run(args: argparse.Namespace) -> int:
    repo = Path(__file__).resolve().parents[1]
    raw = args.source.resolve(strict=True)
    state = args.state
    require(state.exists() and state.is_file() and not state.is_symlink(),
            "private checkpoint absent or symlink")
    require(state.stat().st_mode & 0o777 == 0o600, "checkpoint must be mode 0600")
    require(raw != state.resolve(), "source aliases private checkpoint")
    require(1 <= args.max_steps <= 1000 and 45 <= args.wall_seconds <= 1800,
            "invalid wall/step budget")
    require(1 <= args.rows_per_step <= 20_000 and
            1 <= args.budget_seconds < args.hard_seconds <= 45,
            "invalid batch bounds")
    require(64 * 1024 <= args.max_rss_kib <= 1024 * 1024,
            "invalid observed RSS stop threshold")
    require(1 <= args.min_data_gib <= 100 and 1 <= args.min_root_gib <= 100,
            "invalid capacity reserve")
    require(cmd_output("git", "rev-parse", "HEAD", cwd=repo) == args.require_sha,
            "Traffic checkout not at operator-pinned commit")
    require(not cmd_output("git", "status", "--porcelain", cwd=repo),
            "Traffic checkout dirty")
    require_worker_priority()
    resource_headroom(state, args.min_data_gib, args.min_root_gib)

    lock_path = state.parent / ".canary.lock"
    lock_fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("STOP: another shadow replay holds the lock")
        start_info = checkpoint_info(state)
        verify_frozen(raw, state, start_info)
        receipt_path = state.parent / (
            "v2-pass2-guarded-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            + ".jsonl"
        )
        receipt_fd = open_private_file(receipt_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            record(receipt_fd, {
                "event": "START", "at": utc(), "source_sha": args.require_sha,
                "from_raw": int(start_info["p2_raw"]),
                "checkpoint_phase": start_info["phase"],
                "receipt": str(receipt_path),
                "publication_authorized": False,
            })
            started = time.monotonic()
            steps = 0
            reason = "max_steps"
            with tempfile.TemporaryDirectory(dir=state.parent, prefix=".v2-rss-") as tmp:
                metrics = Path(tmp) / "batch.txt"
                while steps < args.max_steps:
                    remaining = args.wall_seconds - (time.monotonic() - started)
                    if remaining < args.hard_seconds + 10:
                        reason = "wall_budget"
                        break
                    require_worker_priority()
                    resource_headroom(state, args.min_data_gib, args.min_root_gib)
                    if not worker_idle():
                        reason = "project_worker_priority"
                        break
                    before = checkpoint_info(state)
                    verify_frozen(raw, state, before)
                    if before["phase"] == "PASS2_COMPLETE":
                        reason = "PASS2_COMPLETE"
                        break
                    outcome, elapsed, rss = run_one(
                        raw, state, max_rows=args.rows_per_step,
                        budget_seconds=args.budget_seconds,
                        hard_seconds=args.hard_seconds,
                        metrics_path=metrics, repo=repo,
                    )
                    after = checkpoint_info(state)
                    verify_frozen(raw, state, after)
                    delta = int(after["p2_raw"]) - int(before["p2_raw"])
                    require(0 <= delta <= args.rows_per_step,
                            "unbounded replay cursor movement")
                    require(delta > 0 or after["phase"] == "PASS2_COMPLETE",
                            "replay made no forward progress")
                    require(outcome["total_raw"] == int(after["p2_raw"]),
                            "child receipt/cursor mismatch")
                    steps += 1
                    record(receipt_fd, {
                        "event": "STEP", "at": utc(), "batch": steps,
                        "rows": delta, "total_raw": int(after["p2_raw"]),
                        "elapsed_seconds": elapsed, "peak_rss_kib": rss,
                        "phase": after["phase"], "publication_authorized": False,
                    })
                    if after["phase"] == "PASS2_COMPLETE":
                        reason = "PASS2_COMPLETE"
                        break
                    if elapsed > args.max_elapsed_seconds or rss > args.max_rss_kib:
                        reason = "performance_soft_stop"
                        break
                    if not worker_idle():
                        reason = "project_worker_priority"
                        break
            final = checkpoint_info(state)
            verify_frozen(raw, state, final)
            record(receipt_fd, {
                "event": "STOP", "at": utc(), "reason": reason,
                "steps": steps, "p2_raw": int(final["p2_raw"]),
                "p2_accepted": int(final["p2_accepted"]),
                "phase": final["phase"],
                "source_pass_digest_equal": (
                    final["phase"] == "PASS2_COMPLETE"
                    and final["p2_digest"] == FROZEN_DIGEST
                ),
                "publication_authorized": False,
            })
            return 0
        finally:
            os.close(receipt_fd)
    finally:
        os.close(lock_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--require-sha", required=True)
    parser.add_argument("--max-steps", type=int, default=240)
    parser.add_argument("--wall-seconds", type=int, default=900)
    parser.add_argument("--rows-per-step", type=int, default=20_000)
    parser.add_argument("--budget-seconds", type=int, default=25)
    parser.add_argument("--hard-seconds", type=int, default=35)
    parser.add_argument("--max-elapsed-seconds", type=float, default=18)
    parser.add_argument("--max-rss-kib", type=int, default=196608)
    parser.add_argument("--min-data-gib", type=int, default=12)
    parser.add_argument("--min-root-gib", type=int, default=6)
    args = parser.parse_args()
    try:
        return run(args)
    except (RuntimeError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print(f"SAFE STOP: {exc}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

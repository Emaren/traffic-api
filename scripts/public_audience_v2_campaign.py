#!/usr/bin/env python3
"""Bounded, restartable Traffic public audience V2 SHADOW campaign. NO PUBLISH."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import sys

# Support both 'python -m scripts.public_audience_v2_campaign' and direct-script use.
# A direct script starts with scripts/ on sys.path, not the repository root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.traffic.config import PERSIST_DB_PATH
from scripts import public_audience_v2_checkpoint as pass1
from scripts import public_audience_v2_sessions as pass2
from scripts import rebuild_public_audience_archive as canonical


def audit(checkpoint: Path) -> dict:
    report = pass1.status(checkpoint)
    if report["phase"] == "PASS2_COMPLETE":
        days = pass2.shadow_daily(checkpoint)
        for day, (total, suspected, confirmed) in days.items():
            if not (total >= suspected >= confirmed >= 0):
                raise RuntimeError("STOP: shadow hierarchy violation on " + day)
        report["shadow_days"] = len(days)
        report["shadow_utc_first"] = next(iter(days), None)
        report["shadow_utc_last"] = next(reversed(days), None) if days else None
        report["shadow_digest_sha256"] = hashlib.sha256(
            json.dumps(days, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        report["source_parity"] = True
    report["publish_authorized"] = False
    report["semantic_equivalence_certified"] = False
    return report


def cycle(source: Path, checkpoint: Path, *, start: str, end: str,
          rows_per_step: int, step_budget: float,
          wall_seconds: float, max_steps: int) -> dict:
    if not 1 <= max_steps <= 10000 or not 5 <= wall_seconds <= 1800:
        raise RuntimeError("STOP: bounded cycle required")
    if not 1 <= rows_per_step <= 20000 or not 1 <= step_budget <= 120:
        raise RuntimeError("STOP: invalid per-step budget")
    started = time.monotonic()
    steps = 0
    last = None
    while steps < max_steps and time.monotonic() - started < wall_seconds - 2:
        if checkpoint.is_file():
            state = pass1.status(checkpoint)
            phase = state["phase"]
        else:
            phase = "NEW"
        if phase == "PASS2_COMPLETE":
            break
        if phase in ("NEW", "PASS1_RUNNING"):
            last = pass1.advance(
                source, checkpoint, start=start, end=end,
                max_rows=rows_per_step,
                budget_seconds=min(step_budget, max(1, wall_seconds - (time.monotonic()-started) - 1)),
            )
        elif phase in ("PASS1_COMPLETE", "PASS2_RUNNING"):
            last = pass2.pass2_step(
                source, checkpoint, max_rows=rows_per_step,
                budget_seconds=min(step_budget, max(1, wall_seconds - (time.monotonic()-started) - 1)),
            )
        else:
            raise RuntimeError("STOP: unknown checkpoint phase")
        steps += 1
        if last["phase"] == "PASS2_COMPLETE":
            break
    result = audit(checkpoint)
    return {
        "phase": result["phase"],
        "steps": steps,
        "elapsed_seconds": round(time.monotonic()-started, 2),
        "raw_scanned_first_pass": result["raw_scanned"],
        "source_max_rowid": result["source_max_rowid"],
        "shadow_days": result.get("shadow_days"),
        "shadow_digest_sha256": result.get("shadow_digest_sha256"),
        "source_parity": result.get("source_parity", False),
        "publish_authorized": False,
        "semantic_equivalence_certified": False,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("command", choices=("status", "cycle"))
    cli.add_argument("--state", type=Path, required=True)
    cli.add_argument("--source", type=Path, default=PERSIST_DB_PATH)
    cli.add_argument("--start", default=canonical.utc_midnight(canonical.DEFAULT_START).isoformat())
    cli.add_argument("--end", default=canonical.utc_midnight(datetime.now(timezone.utc).date()).isoformat())
    cli.add_argument("--rows-per-step", type=int, default=2000)
    cli.add_argument("--step-budget", type=float, default=15)
    cli.add_argument("--wall-seconds", type=float, default=120)
    cli.add_argument("--max-steps", type=int, default=80)
    opts=cli.parse_args()
    report=(audit(opts.state) if opts.command=="status" else cycle(
        opts.source, opts.state,
        start=pass1._utc_boundary(opts.start),
        end=pass1._utc_boundary(opts.end),
        rows_per_step=opts.rows_per_step,
        step_budget=opts.step_budget,
        wall_seconds=opts.wall_seconds,
        max_steps=opts.max_steps,
    ))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

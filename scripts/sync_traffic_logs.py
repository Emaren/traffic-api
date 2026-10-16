#!/usr/bin/env python3
"""Run the existing idempotent Traffic log sync outside interactive API requests.

Stage 1 only: installing this worker does not change API behavior. Activate the
systemd timer only after confirming the production paths and writer permissions.
"""
from __future__ import annotations

import sys
from pathlib import Path
from time import perf_counter

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.traffic.persistence import (
    persistence_enabled,
    sync_configured_logs_to_persistence,
)


def main() -> int:
    if not persistence_enabled():
        print("traffic_ingest status=disabled", flush=True)
        return 2

    started = perf_counter()
    results = sync_configured_logs_to_persistence()
    modes = [str(result.get("mode", "")) for result in results]
    processed_rows = sum(int(result.get("inserted", 0)) for result in results)
    duration = perf_counter() - started
    print(
        f"traffic_ingest status={'ok' if 'persisted' in modes else 'no_source'} "
        f"sources={len(results)} persisted_sources={modes.count('persisted')} "
        f"processed_rows={processed_rows} duration_s={duration:.3f}",
        flush=True,
    )
    # A missing/misconfigured log source must remain visible to systemd, rather
    # than look like a healthy ingestion timer while all visits go stale.
    return 0 if "persisted" in modes else 2


if __name__ == "__main__":
    raise SystemExit(main())

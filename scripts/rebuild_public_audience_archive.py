#!/usr/bin/env python3
from __future__ import annotations

import argparse
import heapq
import sqlite3
import sys
from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.services.traffic.classify import classify_request, detect_route_kind
from app.services.traffic.config import (
    PERSIST_DB_PATH,
    PROJECTS,
    SESSION_GAP_MINUTES,
)
from app.services.traffic.normalize import (
    is_allowed_host,
    normalize_host,
    normalize_referrer,
    project_for_host,
)
from app.services.traffic.overview import should_ignore_entry
from app.services.traffic.parse import parse_iso_timestamp
from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from app.services.traffic.sessions import (
    ROTATING_UA_ROUTE_SPAM_DIRECT_RATIO,
    ROTATING_UA_ROUTE_SPAM_MAX_UNIQUE_PATHS,
    ROTATING_UA_ROUTE_SPAM_MIN_REQUESTS,
    ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_PATHS,
    ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_UAS,
    UNKNOWN_HOST,
    UNKNOWN_REFERRER,
    _is_framework_route_bundle_path,
    _is_known_singapore_cloud_fanout,
    apply_known_visitor_confirmation,
    build_single_session,
    collapse_distributed_bursts,
)
from app.services.traffic.visibility import (
    entry_hidden_by_visibility_rules,
    safe_list_visibility_rules,
)

PROJECT_SLUG = "aoe2hdbets"
DEFAULT_START = date(2026, 5, 22)
BURST_SECONDS = 60


def utc_midnight(value: date) -> datetime:
    return datetime.combine(value, time.min, tzinfo=timezone.utc)


def project_hosts() -> list[str]:
    project = next(
        item for item in PROJECTS
        if item.get("slug") == PROJECT_SLUG
    )
    return sorted(
        {
            normalize_host(str(host))
            for host in project.get("hosts", [])
            if host
        }
    )


def source_rows(
    *,
    start: datetime,
    end: datetime,
    snapshot_max_rowid: int,
) -> Iterator[sqlite3.Row]:
    db = PERSIST_DB_PATH.resolve()
    hosts = project_hosts()
    placeholders = ",".join("?" for _ in hosts)
    firehose = _non_browser_chain_firehose_sql()

    connection = sqlite3.connect(
        f"file:{db}?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row

    try:
        cursor = connection.execute(
            f"""
            SELECT
                rowid AS source_rowid,
                event_id,
                timestamp,
                ip,
                line_offset,
                raw_path,
                normalized_path,
                referrer_host,
                ua,
                host
            FROM traffic_entries
                INDEXED BY idx_traffic_entries_timestamp_line_offset
            WHERE
                timestamp >= ?
                AND timestamp < ?
                AND rowid <= ?
                AND host IN ({placeholders})
                AND ({firehose})
            ORDER BY
                timestamp ASC,
                line_offset ASC,
                rowid ASC
            """,
            (
                start.isoformat(),
                end.isoformat(),
                snapshot_max_rowid,
                *hosts,
            ),
        )

        for row in cursor:
            yield row

    finally:
        connection.close()


def normalize_row(
    row: sqlite3.Row,
    *,
    rules: list[dict[str, Any]],
) -> dict[str, Any] | None:
    timestamp = parse_iso_timestamp(row["timestamp"])
    if timestamp is None:
        return None

    item: dict[str, Any] = {
        "event_id": str(row["event_id"] or ""),
        "ip": str(row["ip"] or ""),
        "timestamp": timestamp,
        "timestamp_iso": str(row["timestamp"]),
        "line_offset": int(row["line_offset"] or 0),
        "raw_path": str(row["raw_path"] or ""),
        "normalized_path": str(row["normalized_path"] or ""),
        "referrer_host": normalize_referrer(
            str(row["referrer_host"] or "")
        ),
        "ua": str(row["ua"] or ""),
        "host": normalize_host(str(row["host"] or "")),
    }

    if not is_allowed_host(item["host"]):
        return None

    if project_for_host(item["host"]).get("slug") != PROJECT_SLUG:
        return None

    item["category"] = classify_request(
        item["ua"],
        item["normalized_path"],
    )
    item["route_kind"] = detect_route_kind(
        item["normalized_path"]
    )

    if entry_hidden_by_visibility_rules(
        item,
        rules=rules,
    ):
        return None

    if should_ignore_entry(item):
        return None

    return item


def build_ip_behavior(
    *,
    start: datetime,
    end: datetime,
    snapshot_max_rowid: int,
) -> tuple[dict[tuple[str, str], dict[str, Any]], int, int]:
    rules = safe_list_visibility_rules(active_only=True)

    stats: dict[tuple[str, str], dict[str, Any]] = {}

    raw_count = 0
    accepted_count = 0

    for row in source_rows(
        start=start,
        end=end,
        snapshot_max_rowid=snapshot_max_rowid,
    ):
        raw_count += 1

        item = normalize_row(row, rules=rules)
        if item is None:
            continue

        accepted_count += 1

        key = (
            item["host"],
            item["ip"],
        )

        stat = stats.get(key)

        if stat is None:
            stat = {
                "request_count": 0,
                "uas": set(),
                "paths": set(),
                "direct_referrers": 0,
            }
            stats[key] = stat

        stat["request_count"] += 1

        ua = (item.get("ua") or "").lower().strip()
        if ua:
            stat["uas"].add(ua)

        stat["paths"].add(
            item["normalized_path"]
        )

        if (
            item.get("referrer_host") or UNKNOWN_REFERRER
        ) in {
            UNKNOWN_REFERRER,
            "",
            UNKNOWN_HOST,
        }:
            stat["direct_referrers"] += 1

        if raw_count % 250_000 == 0:
            print(
                "pass1:",
                f"raw={raw_count:,}",
                f"accepted={accepted_count:,}",
                f"ips={len(stats):,}",
                flush=True,
            )

    behavior: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    for key, stat in stats.items():
        request_count = int(stat["request_count"])
        uas = stat["uas"]
        paths = stat["paths"]

        direct_ratio = (
            stat["direct_referrers"] / request_count
            if request_count
            else 0.0
        )

        route_bundle_spam = (
            request_count
            >= ROTATING_UA_ROUTE_SPAM_MIN_REQUESTS
            and len(uas)
            >= ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_UAS
            and ROTATING_UA_ROUTE_SPAM_MIN_UNIQUE_PATHS
            <= len(paths)
            <= ROTATING_UA_ROUTE_SPAM_MAX_UNIQUE_PATHS
            and all(
                _is_framework_route_bundle_path(path)
                for path in paths
            )
            and direct_ratio
            >= ROTATING_UA_ROUTE_SPAM_DIRECT_RATIO
        )

        behavior[key] = {
            "request_count": request_count,
            "unique_uas": len(uas),
            "unique_paths": len(paths),
            "route_bundle_paths": sorted(paths),
            "route_bundle_spam": route_bundle_spam,
        }

    return behavior, raw_count, accepted_count


def bucket_id(value: datetime) -> int:
    return int(value.timestamp() // BURST_SECONDS)


def finalize_bucket(
    sessions: list[dict[str, Any]],
    daily: dict[str, list[int]],
) -> int:
    if not sessions:
        return 0

    original_ids = {
        str(session["session_id"])
        for session in sessions
    }

    collapsed = collapse_distributed_bursts(
        sessions
    )

    surviving_original_ids = {
        str(session["session_id"])
        for session in collapsed
        if str(session.get("session_id", ""))
        in original_ids
    }

    burst_member_ids = (
        original_ids
        - surviving_original_ids
    )

    emitted = 0

    for session in sessions:
        session_id = str(session["session_id"])

        synthetic_burst = (
            session_id in burst_member_ids
        )

        singapore_script = (
            _is_known_singapore_cloud_fanout(
                session
            )
        )

        if singapore_script:
            session["classification_state"] = "browser_script"
            session["human_confirmed"] = False
            session["human_confidence"] = 0
            session["suspicious_score"] = max(
                int(
                    session.get(
                        "suspicious_score",
                        0,
                    )
                    or 0
                ),
                76,
            )

        apply_known_visitor_confirmation(
            session
        )

        if session.get("route_kind") != "page":
            continue

        day = str(
            session.get(
                "first_seen_at",
                "",
            )
        )[:10]

        if not day:
            continue

        if day not in daily:
            daily[day] = [0, 0, 0]

        daily[day][0] += 1

        suspected = bool(
            not synthetic_burst
            and not singapore_script
            and not session.get(
                "known_automation"
            )
            and int(
                session.get(
                    "suspicious_score",
                    0,
                )
                or 0
            )
            < 35
            and session.get(
                "classification_state"
            )
            in {
                "likely_human",
                "human_confirmed",
            }
        )

        confirmed = bool(
            suspected
            and session.get(
                "classification_state"
            )
            == "human_confirmed"
        )

        if suspected:
            daily[day][1] += 1

        if confirmed:
            daily[day][2] += 1

        emitted += 1

    return emitted


def stream_sessions(
    *,
    start: datetime,
    end: datetime,
    behavior: dict[tuple[str, str], dict[str, Any]],
    snapshot_max_rowid: int,
) -> tuple[dict[str, list[int]], dict[str, int]]:
    rules = safe_list_visibility_rules(active_only=True)

    open_sessions: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}

    expiry_heap: list[
        tuple[float, int, tuple[str, str, str]]
    ] = []

    bucket_open_counts: dict[int, int] = defaultdict(int)
    bucket_sessions: dict[
        int,
        list[dict[str, Any]],
    ] = defaultdict(list)

    zero_bucket_heap: list[int] = []

    daily: dict[str, list[int]] = {}

    raw_count = 0
    accepted_count = 0
    finalized_sessions = 0
    emitted_page_sessions = 0
    version_counter = 0

    gap = timedelta(
        minutes=SESSION_GAP_MINUTES
    )

    now = datetime.now(timezone.utc)

    def close_session(
        key: tuple[str, str, str],
        state: dict[str, Any],
        current_time: datetime,
    ) -> None:
        nonlocal finalized_sessions

        events = state["events"]
        if not events:
            return

        first = events[0]

        session = build_single_session(
            events,
            now=now,
            ip_behavior=behavior.get(
                (
                    first["host"],
                    first["ip"],
                ),
                {},
            ),
        )

        b_id = state["bucket_id"]

        bucket_sessions[b_id].append(
            session
        )

        bucket_open_counts[b_id] -= 1

        if bucket_open_counts[b_id] == 0:
            heapq.heappush(
                zero_bucket_heap,
                b_id,
            )

        finalized_sessions += 1

    def expire_before(
        current_time: datetime,
    ) -> None:
        while expiry_heap:
            expiry_ts, version, key = expiry_heap[0]

            if expiry_ts >= current_time.timestamp():
                break

            heapq.heappop(
                expiry_heap
            )

            state = open_sessions.get(
                key
            )

            if state is None:
                continue

            if state["version"] != version:
                continue

            close_session(
                key,
                state,
                current_time,
            )

            del open_sessions[key]

    def flush_ready_buckets(
        current_time: datetime,
    ) -> None:
        nonlocal emitted_page_sessions

        current_bucket = bucket_id(
            current_time
        )

        while zero_bucket_heap:
            b_id = zero_bucket_heap[0]

            if b_id >= current_bucket:
                break

            heapq.heappop(
                zero_bucket_heap
            )

            if bucket_open_counts.get(
                b_id,
                0,
            ) != 0:
                continue

            sessions = bucket_sessions.pop(
                b_id,
                [],
            )

            emitted_page_sessions += (
                finalize_bucket(
                    sessions,
                    daily,
                )
            )

            bucket_open_counts.pop(
                b_id,
                None,
            )

    for row in source_rows(
        start=start,
        end=end,
        snapshot_max_rowid=snapshot_max_rowid,
    ):
        raw_count += 1

        item = normalize_row(
            row,
            rules=rules,
        )

        if item is None:
            continue

        accepted_count += 1

        current_time = item["timestamp"]

        expire_before(
            current_time
        )

        flush_ready_buckets(
            current_time
        )

        key = (
            item["host"],
            item["ip"],
            (item.get("ua") or "").lower(),
        )

        state = open_sessions.get(
            key
        )

        if state is None:
            version_counter += 1

            b_id = bucket_id(
                current_time
            )

            state = {
                "events": [item],
                "last_time": current_time,
                "version": version_counter,
                "bucket_id": b_id,
            }

            open_sessions[key] = state
            bucket_open_counts[b_id] += 1

        else:
            # expire_before() guarantees the gap is <= 30 minutes.
            state["events"].append(
                item
            )
            state["last_time"] = current_time

            version_counter += 1
            state["version"] = version_counter

        heapq.heappush(
            expiry_heap,
            (
                (
                    state["last_time"]
                    + gap
                ).timestamp(),
                state["version"],
                key,
            ),
        )

        if raw_count % 250_000 == 0:
            print(
                "pass2:",
                f"raw={raw_count:,}",
                f"accepted={accepted_count:,}",
                f"open={len(open_sessions):,}",
                f"finalized={finalized_sessions:,}",
                flush=True,
            )

    for key, state in list(
        open_sessions.items()
    ):
        close_session(
            key,
            state,
            end,
        )

    open_sessions.clear()

    for b_id in sorted(
        bucket_sessions
    ):
        emitted_page_sessions += (
            finalize_bucket(
                bucket_sessions[b_id],
                daily,
            )
        )

    return daily, {
        "raw_rows": raw_count,
        "accepted_rows": accepted_count,
        "finalized_sessions": finalized_sessions,
        "page_sessions": emitted_page_sessions,
    }


def apply_daily_rollups(
    daily: dict[str, list[int]],
) -> None:
    rows = []

    updated_at = datetime.now(
        timezone.utc
    ).isoformat()

    for day in sorted(daily):
        total, suspected, confirmed = daily[day]

        if not (
            total
            >= suspected
            >= confirmed
        ):
            raise RuntimeError(
                f"Hierarchy violation on {day}: "
                f"{total} / {suspected} / {confirmed}"
            )

        rows.append(
            (
                PROJECT_SLUG,
                day,
                total,
                suspected,
                confirmed,
                updated_at,
            )
        )

    connection = sqlite3.connect(
        PERSIST_DB_PATH.resolve(),
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA busy_timeout=30000"
    )

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS
            traffic_public_daily_audience_rollups (
                project_slug TEXT NOT NULL,
                bucket_day TEXT NOT NULL,
                total_traffic INTEGER
                    NOT NULL DEFAULT 0,
                suspected_human INTEGER
                    NOT NULL DEFAULT 0,
                confirmed_human INTEGER
                    NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (
                    project_slug,
                    bucket_day
                )
            )
            """
        )

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        connection.execute(
            """
            DELETE FROM
                traffic_public_daily_audience_rollups
            WHERE project_slug = ?
            """,
            (PROJECT_SLUG,),
        )

        connection.executemany(
            """
            INSERT INTO
                traffic_public_daily_audience_rollups (
                    project_slug,
                    bucket_day,
                    total_traffic,
                    suspected_human,
                    confirmed_human,
                    updated_at
                )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

        bad = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM
                traffic_public_daily_audience_rollups
            WHERE
                project_slug = ?
                AND NOT (
                    total_traffic
                        >= suspected_human
                    AND suspected_human
                        >= confirmed_human
                )
            """,
            (PROJECT_SLUG,),
        ).fetchone()

        bad_count = int(
            bad["total"]
            if bad
            else 0
        )

        if bad_count:
            raise RuntimeError(
                "Persisted hierarchy validation "
                f"failed for {bad_count} days."
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    print()
    print(
        "APPLIED DAILY ROLLUPS:",
        len(rows),
    )



def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--start",
        default=DEFAULT_START.isoformat(),
    )

    parser.add_argument(
        "--end",
        default=None,
    )

    parser.add_argument(
        "--apply",
        action="store_true",
    )

    args = parser.parse_args()

    start = utc_midnight(
        date.fromisoformat(
            args.start
        )
    )

    end = (
        datetime.fromisoformat(
            args.end
        ).astimezone(timezone.utc)
        if args.end
        else datetime.now(timezone.utc)
    )

    print(
        "database:",
        PERSIST_DB_PATH.resolve(),
    )
    print(
        "start:",
        start.isoformat(),
    )
    print(
        "end:",
        end.isoformat(),
    )

    snapshot_connection = sqlite3.connect(
        f"file:{PERSIST_DB_PATH.resolve()}?mode=ro",
        uri=True,
    )

    try:
        snapshot_row = snapshot_connection.execute(
            """
            SELECT COALESCE(MAX(rowid), 0)
            FROM traffic_entries
            WHERE timestamp < ?
            """,
            (end.isoformat(),),
        ).fetchone()

        snapshot_max_rowid = int(
            snapshot_row[0]
            if snapshot_row
            else 0
        )
    finally:
        snapshot_connection.close()

    print(
        "snapshot_max_rowid:",
        snapshot_max_rowid,
    )

    print()
    print(
        "PASS 1 — IP BEHAVIOR"
    )

    behavior, pass1_raw, pass1_accepted = (
        build_ip_behavior(
            start=start,
            end=end,
            snapshot_max_rowid=snapshot_max_rowid,
        )
    )

    print(
        "pass1 complete:",
        f"raw={pass1_raw:,}",
        f"accepted={pass1_accepted:,}",
        f"ip_keys={len(behavior):,}",
    )

    print()
    print(
        "PASS 2 — SESSIONIZATION"
    )

    daily, stats = stream_sessions(
        start=start,
        end=end,
        behavior=behavior,
        snapshot_max_rowid=snapshot_max_rowid,
    )

    print(
        "pass2 complete:",
        f"raw={stats['raw_rows']:,}",
        f"accepted={stats['accepted_rows']:,}",
        f"sessions={stats['finalized_sessions']:,}",
        f"page_sessions={stats['page_sessions']:,}",
    )

    print()
    print(
        "DAILY CANARY"
    )

    violations = 0

    for day in sorted(daily):
        total, suspected, confirmed = daily[day]

        if not (
            total >= suspected >= confirmed
        ):
            violations += 1

        print(
            day,
            f"total={total}",
            f"suspected={suspected}",
            f"confirmed={confirmed}",
        )

    print()
    print(
        "hierarchy_violations:",
        violations,
    )

    if violations:
        raise SystemExit(
            "FAIL: hierarchy violation."
        )

    if args.apply:
        if start.date() != DEFAULT_START:
            raise SystemExit(
                "STOP: --apply is only allowed "
                "from the canonical 2026-05-22 start."
            )

        print()
        print(
            "APPLYING CANONICAL DAILY ROLLUPS"
        )

        apply_daily_rollups(
            daily
        )

        print()
        print(
            "FULL CANONICAL FORGE COMPLETE"
        )

    else:
        print()
        print(
            "CANARY COMPLETE — NO DATABASE WRITES"
        )


if __name__ == "__main__":
    main()

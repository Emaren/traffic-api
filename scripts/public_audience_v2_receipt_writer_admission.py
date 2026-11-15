#!/usr/bin/env python3
"""Source-only review of exact Traffic insertion-receipt flag and inverse.

NO INSTALL/START/STOP/RESTART/DAEMON-RELOAD/ROOT OR SQLITE WRITES.
This module prepares a deterministic candidate for independent WE1/B and C03
source/physical approval. It is not a permit or operator installer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import os
import stat
import subprocess
import sys

SCHEMA = "traffic.v2.ingest-receipt-protected-footprint-review.v1"
CURRENT_SOURCE_SHA = "60cf4da5962b4ba65f546d2bea68c3cdc03e8479"
SERVICE_SHA256 = "ae9a923682906032343b96fb33c62ab61ed3a40c20e5d4755a78cddbb83dbac9"
TIMER_SHA256 = "c78379c9a44e2980ff3285d2b93785c0b949ea88efc3a28ea080e33b6b4441e0"
PERSISTENCE_SHA256 = "9863f6b6eae5986793d355486612b63ddf058624e627acac34d8303907e017e5"
INGEST_SCRIPT_SHA256 = "1c65870461abf1c16c6067e5b93dffde03923a5e57ac066a11b1e4d3f42a615d"
STEAM_V27_SHA256 = "2695a5b5fb4adf9e17afbb30c535158260608b8ba60e13fea4b2e4da29e974ca"
STEAM_ROOT_PIN_SHA256 = "9799d8c9042dbd1875a2096ee1df6b8751347206cf8761d695aecf1e61894707"
TRAFFIC_API_SHA256 = "fbb43b0d050cb3894bb7099aa71a5076f8996f59c6f3ccf7c80a28ef2d5efa40"
TRAFFIC_API_INLINE_HANDOFF_SHA256 = "257edd0bfc86039255a955297f2e51bff6144daa0c644e136dcc34dd525eca7f"
TRAFFIC_API_EFFECTIVE_SHA256 = "ef5f7b2b0b64611dbb136ef2def4e0264acdb44ce0868100194792acf10b85cb"
DROPIN_PATH = "/etc/systemd/system/traffic-ingest.service.d/90-traffic-v2-insertion-receipts-only.conf"
DROPIN = b"[Service]\nEnvironment=TRAFFIC_INGEST_RECEIPTS_ENABLED=1\n"
ALLOWED_INVERSE = "REMOVE_EXACT_ADDED_DROPIN_ONLY_AFTER_SHA256_CHECK_AND_DAEMON_RELOAD"
EXISTING_WRITER = (
    "ExecStart=/usr/bin/flock -n -E 75 /run/traffic-ingest/sync.lock "
    "/var/www/Traffic/traffic-api/.venv/bin/python3 scripts/sync_traffic_logs.py"
)


def need(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError("HOLD:" + message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_unit_preimage(service: bytes, timer: bytes,
                           persistence: bytes, ingest: bytes,
                           steam: bytes, original: bytes,
                           *, dropin_preexists: bool = False) -> dict:
    """Independent caller must supply real byte readbacks; this is pure."""
    for name, data, expected in (
        ("traffic-ingest.service", service, SERVICE_SHA256),
        ("traffic-ingest.timer", timer, TIMER_SHA256),
        ("app/services/traffic/persistence.py", persistence, PERSISTENCE_SHA256),
        ("scripts/sync_traffic_logs.py", ingest, INGEST_SCRIPT_SHA256),
        ("r25_steam_refresh_product_v27.py", steam, STEAM_V27_SHA256),
        ("r25_c_start_root.py", original, STEAM_ROOT_PIN_SHA256),
    ):
        need(type(data) is bytes and digest(data) == expected,
             "EXACT_SOURCE_PIN_DRIFT_" + name.replace("/", "_"))
    need(not dropin_preexists, "RECEIPT_DROPIN_ALREADY_PRESENT")
    need(service.count(EXISTING_WRITER.encode()) == 1,
         "ORIGINAL_SINGLE_WRITER_FLOCK_COMMAND_DRIFT")
    need(b"User=tony\n" in service and b"Group=tony\n" in service,
         "INGESTION_PRINCIPAL_DRIFT")
    for control in (
        b"PrivateNetwork=yes", b"NoNewPrivileges=yes",
        b"ProtectSystem=strict", b"CapabilityBoundingSet=",
        b"ReadWritePaths=/mnt/HC_Volume_105319120/traffic-db /run/traffic-ingest",
        b"InaccessiblePaths=-/run/postgresql -/var/run/postgresql",
    ):
        need(control in service, "INGESTION_SANDBOX_DRIFT")
    need(b"OnUnitInactiveSec=2min\n" in timer
         and b"Unit=traffic-ingest.service\n" in timer,
         "ORIGINAL_TIMER_IDENTITY_DRIFT")
    need(b"TRAFFIC_INGEST_RECEIPTS_ENABLED" in persistence
         and b"ingested_at_utc" in persistence
         and b"strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')" in persistence,
         "ORIGINAL_INSERT_RECEIPT_CODE_UNAVAILABLE")
    return manifest()


def manifest() -> dict:
    """Manifest never asserts independent authority or readiness to install."""
    need(DROPIN.count(b"\n") == 2
         and DROPIN.decode("ascii").splitlines() == [
             "[Service]", "Environment=TRAFFIC_INGEST_RECEIPTS_ENABLED=1"
         ], "ONE_FLAG_SCOPE_DRIFT")
    return {
        "schema": SCHEMA,
        "traffic_installed_source_sha": CURRENT_SOURCE_SHA,
        "preimage_sha256": {
            "traffic_ingest_service": SERVICE_SHA256,
            "traffic_ingest_timer": TIMER_SHA256,
            "traffic_persistence": PERSISTENCE_SHA256,
            "traffic_sync_script": INGEST_SCRIPT_SHA256,
            "steam_v27": STEAM_V27_SHA256,
            "steam_root_source": STEAM_ROOT_PIN_SHA256,
            "traffic_api_unit": TRAFFIC_API_SHA256,
            "traffic_api_inline_handoff_dropin": TRAFFIC_API_INLINE_HANDOFF_SHA256,
            "traffic_api_full_effective_unit": TRAFFIC_API_EFFECTIVE_SHA256,
        },
        "dropin_path": DROPIN_PATH,
        "dropin_proposed_bytes_utf8": DROPIN.decode("ascii"),
        "dropin_proposed_sha256": digest(DROPIN),
        "dropin_preimage": "ABSENT",
        "single_existing_flock_writer_unchanged": True,
        "also_requires_api_inline_ingest_disabled": True,
        "root_operator_ownership_required": True,
        "required_independent_approvals": [
            "WE1_C03_PROTECTED_SERVICE_SOURCE_AND_FINANCE_CENSUS",
            "B_STEAM_V27_PROTECTED_FOOTPRINT_REENROLLMENT",
            "AUTHORIZED_TRAFFIC_DATA_PLANE_OPERATOR",
        ],
        "inverse": {
            "action": ALLOWED_INVERSE,
            "only_when_actual_dropin_sha256": digest(DROPIN),
            "restore_preimage": "ABSENT",
            "requires_independent_root_invocation": True,
            "verify_original_unit_digests_after_reload": True,
        },
        "approved_by": None,
        "install_authorized": False,
        "systemd_mutation": False,
        "sqlite_mutation": False,
        "financial_authorized": False,
        "old_null_receipts_backfilled": False,
        "public_audience_publication_authorized": False,
    }


def inverse_decision(*, actual: bytes | None, preimage_absent: bool,
                     original_service_sha: str, original_timer_sha: str) -> str:
    """A testable inverse gate, NOT an execution function."""
    need(preimage_absent, "UNKNOWN_PREEXISTING_DROPIN")
    need(type(actual) is bytes and digest(actual) == digest(DROPIN),
         "DROPIN_POSTIMAGE_DRIFT")
    need(original_service_sha == SERVICE_SHA256 and
         original_timer_sha == TIMER_SHA256,
         "ORIGINAL_UNIT_PREIMAGE_DRIFT")
    return ALLOWED_INVERSE



SOURCE_ROOT_FILES = {
    "service": Path("/etc/systemd/system/traffic-ingest.service"),
    "timer": Path("/etc/systemd/system/traffic-ingest.timer"),
    "persistence": Path("/var/www/Traffic/traffic-api/app/services/traffic/persistence.py"),
    "ingest": Path("/var/www/Traffic/traffic-api/scripts/sync_traffic_logs.py"),
    "steam": Path("/usr/local/lib/aoe2war-web-prod/r25_steam_refresh_product_v27.py"),
    "original": Path("/usr/local/lib/aoe2war-web-prod/r25_c_start_root.py"),
}


def read_installed_pin(path: Path, *, expected_uid: int,
                       expected_mode: int) -> bytes:
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
         and st.st_uid == expected_uid,
         "FILE_OR_OWNER_DRIFT_" + path.name)
    need(st.st_size < 300_000 and st.st_size > 0
         and stat.S_IMODE(st.st_mode) == expected_mode,
         "FILE_MODE_OR_SIZE_DRIFT_" + path.name)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        data = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    need(len(data) == before.st_size and
         (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
         "SOURCE_READ_RACE_" + path.name)
    return data


def check_api_writer_preimage(fragment: bytes, handoff: bytes,
                              effective: bytes) -> None:
    for label, raw, expected in (
        ("API_UNIT", fragment, TRAFFIC_API_SHA256),
        ("API_INLINE_HANDOFF", handoff, TRAFFIC_API_INLINE_HANDOFF_SHA256),
        ("API_FULL_EFFECTIVE", effective, TRAFFIC_API_EFFECTIVE_SHA256),
    ):
        need(digest(raw) == expected, "INLINE_INGEST_SOURCE_DRIFT_" + label)
    need(b"Environment=TRAFFIC_DISABLE_INLINE_INGEST=1" in handoff,
         "INLINE_INGEST_NOT_PINNED_DISABLED")


def show(unit: str, *properties: str) -> dict[str, str]:
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", unit, "--no-pager", "--property=" +
         ",".join(properties)],
        capture_output=True, text=True, timeout=6, check=True,
    )
    return dict(row.split("=", 1) for row in result.stdout.splitlines() if "=" in row)


def inspect_live_no_mutation() -> dict:
    need(sys.platform == "linux" and os.geteuid() == 0,
         "EXACT_LINUX_ROOT_READONLY_PREIMAGE_REQUIRED")
    values = {}
    # Mirror actual installed ownership, including the intentionally
    # owner-UID1000 group-write ingestion script and UID1000 0600 envfile.
    # Their byte digests remain exact pins; this plan does NOT chmod them.
    owners = {
        "service": (0, 0o644), "timer": (0, 0o644),
        "persistence": (0, 0o644), "ingest": (1000, 0o664),
        "steam": (0, 0o700), "original": (0, 0o644),
    }
    for name, path in SOURCE_ROOT_FILES.items():
        uid, mode = owners[name]
        values[name] = read_installed_pin(
            path, expected_uid=uid, expected_mode=mode,
        )
    parent = Path(DROPIN_PATH).parent
    need(parent.is_dir() and not parent.is_symlink(),
         "DROPIN_PARENT_ABSENT_OR_SYMLINK")
    need(not Path(DROPIN_PATH).exists() and
         not Path(DROPIN_PATH).is_symlink(),
         "DROPIN_ALREADY_INSTALLED")
    need(not list(parent.glob("*.conf")), "EXISTING_DROPIN_AUTHORITY_UNKNOWN")
    # Read environment file in private root memory. Never echo its contents.
    # An existing activation through EnvironmentFile is NOT a fresh permit.
    env = read_installed_pin(
        Path("/etc/traffic-api.env"), expected_uid=1000,
        expected_mode=0o600,
    )
    need(all(line.split("=", 1)[0].strip().removeprefix("export ").strip()
             != "TRAFFIC_INGEST_RECEIPTS_ENABLED"
             for line in env.decode("utf-8").splitlines()
             if line.strip() and not line.lstrip().startswith("#")),
         "INGEST_FLAG_ALREADY_IN_ENVFILE")
    api_unit = read_installed_pin(
        Path("/etc/systemd/system/traffic-api.service"),
        expected_uid=0, expected_mode=0o644,
    )
    api_handoff = read_installed_pin(
        Path("/etc/systemd/system/traffic-api.service.d/60-inline-ingest-handoff.conf"),
        expected_uid=0, expected_mode=0o644,
    )
    api_full = subprocess.run(
        ["/usr/bin/systemctl", "cat", "traffic-api.service", "--no-pager"],
        capture_output=True, timeout=6, check=True,
    ).stdout
    check_api_writer_preimage(api_unit, api_handoff, api_full)
    api = show(
        "traffic-api.service",
        "Environment", "ActiveState", "NeedDaemonReload", "MainPID",
    )
    need(api.get("Environment") == "TRAFFIC_DISABLE_INLINE_INGEST=1"
         and api.get("ActiveState") == "active"
         and api.get("NeedDaemonReload") == "no"
         and api.get("MainPID", "").isdecimal()
         and int(api["MainPID"]) > 100,
         "API_INLINE_INGEST_NOT_EXACTLY_DISABLED")

    effective = show(
        "traffic-ingest.service",
        "User", "Group", "DropInPaths", "ExecStart", "Environment",
        "PrivateNetwork", "NoNewPrivileges", "ProtectSystem", "ReadWritePaths",
        "ActiveState", "UnitFileState", "NeedDaemonReload"
    )
    need(effective.get("DropInPaths") == "" and
         effective.get("User") == "tony"
         and effective.get("Group") == "tony"
         and effective.get("ActiveState") == "inactive"
         and effective.get("NeedDaemonReload") == "no"
         and effective.get("PrivateNetwork") == "yes"
         and effective.get("NoNewPrivileges") == "yes"
         and effective.get("ProtectSystem") == "strict"
         and "TRAFFIC_INGEST_RECEIPTS_ENABLED" not in
         effective.get("Environment", "")
         and "/usr/bin/flock -n -E 75" in effective.get("ExecStart", ""),
         "LOADED_SYSTEMD_INGEST_FOOTPRINT_DRIFT_OR_ACTIVE")
    timer = show("traffic-ingest.timer","ActiveState","UnitFileState")
    need(timer.get("ActiveState") == "active"
         and timer.get("UnitFileState") == "enabled",
         "ORIGINAL_INGEST_TIMER_NOT_RUNNING")
    legacy = show("traffic-public-audience-aoe2hdbets.timer","ActiveState","UnitFileState")
    need(legacy.get("ActiveState") == "inactive"
         and legacy.get("UnitFileState") == "disabled",
         "LEGACY_FAILED_PUBLISHER_TIMER_CHANGED")
    steam = show("aoe2war-steam-egress-refresh.service", "Result", "ExecMainStatus")
    need(steam.get("Result") == "success"
         and steam.get("ExecMainStatus") == "0",
         "CURRENT_STEAM_REFRESH_NOT_VERIFIED")
    result = validate_unit_preimage(
        values["service"], values["timer"], values["persistence"],
        values["ingest"], values["steam"], values["original"],
        dropin_preexists=False
    )
    result["live_pin_readback_verified"] = True
    result["effective_original_timer_and_single_writer_verified"] = True
    result["api_inline_ingest_disabled_verified"] = True
    result["steam_v27_last_renewal_success"] = True
    result["legacy_full_history_timer_still_disabled"] = True
    result["root_read_only_preflight_only"] = True
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--phase", choices=["review-only", "inspect-live"], required=True)
    args = ap.parse_args()
    try:
        if args.phase == "review-only":
            print(json.dumps(manifest(), indent=2, sort_keys=True))
            # A review document is not a root or data-plane permit.
            return 2
        if args.phase == "inspect-live":
            print(json.dumps(inspect_live_no_mutation(), indent=2, sort_keys=True))
            # Even a matched physical pin is not a root install permit.
            return 2
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        print(str(e), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

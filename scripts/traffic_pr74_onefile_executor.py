#!/usr/bin/env python3
"""Single-action WE2 Traffic PR74 root executor. Source candidate, NOT a permit.

No freeform command, path, SQL, or generic root authority. The independently
enrolled owner key signs exactly one source-bound action and fresh WE4 witness.
"""
from __future__ import annotations
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time

PURPOSE = "TRAFFIC_PR74_RECEIPT_SETTING_ONLY"
SOURCE_SHA = "6ec52fd7c82ed9f2e536badf56f4f5b1b788b293"
DROPIN_PATH = Path("/etc/systemd/system/traffic-ingest.service.d/90-traffic-v2-insertion-receipts-only.conf")
DROPIN_BYTES = b"[Service]\nEnvironment=TRAFFIC_INGEST_RECEIPTS_ENABLED=1\n"
DROPIN_SHA = "f9a50e57fad5d9f562cafc2b89dde9c7e403f48300d5833871168ab03fc879fe"
ORIGINAL_CAT_SHA = "97b7b6341e17c4b2a90ccadf3c9b42140180443ed53d808c6dcc600c72c56f40"
EXPECTED_CAT_SHA = "1a700eacf9e0494706fbe32111db890a33f7f620592fdfc17ec071ae6781bea9"
API_CAT_SHA = "ef5f7b2b0b64611dbb136ef2def4e0264acdb44ce0868100194792acf10b85cb"
EXPECTED = {
    "/etc/systemd/system/traffic-ingest.service": "ae9a923682906032343b96fb33c62ab61ed3a40c20e5d4755a78cddbb83dbac9",
    "/etc/systemd/system/traffic-ingest.timer": "c78379c9a44e2980ff3285d2b93785c0b949ea88efc3a28ea080e33b6b4441e0",
    "/var/www/Traffic/traffic-api/app/services/traffic/persistence.py": "9863f6b6eae5986793d355486612b63ddf058624e627acac34d8303907e017e5",
    "/var/www/Traffic/traffic-api/scripts/sync_traffic_logs.py": "1c65870461abf1c16c6067e5b93dffde03923a5e57ac066a11b1e4d3f42a615d",
    "/usr/local/lib/aoe2war-web-prod/r25_steam_refresh_product_v27.py": "2695a5b5fb4adf9e17afbb30c535158260608b8ba60e13fea4b2e4da29e974ca",
    "/usr/local/lib/aoe2war-web-prod/r25_c_start_root.py": "9799d8c9042dbd1875a2096ee1df6b8751347206cf8761d695aecf1e61894707",
    "/etc/systemd/system/traffic-api.service": "fbb43b0d050cb3894bb7099aa71a5076f8996f59c6f3ccf7c80a28ef2d5efa40",
    "/etc/systemd/system/traffic-api.service.d/60-inline-ingest-handoff.conf": "257edd0bfc86039255a955297f2e51bff6144daa0c644e136dcc34dd525eca7f",
}
TRUST = Path("/etc/aoe2war/traffic-pr74")
STATE = Path("/var/lib/aoe2war-traffic-pr74")
EXECUTOR = Path("/usr/local/libexec/aoe2war/traffic_pr74_onefile_executor.py")
SQLITE = Path("/mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3")
NGINX = Path("/var/log/nginx/access.log")
SIGNERS = TRUST / "allowed_signers"
WITNESS = TRUST / "we4_preinstall_witness.json"

class Hold(RuntimeError):
    pass

def need(ok, why):
    if not ok:
        raise Hold("HOLD_TRAFFIC_PR74_" + why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def read_single(path, *, root=False, limit=200000):
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit,
         "FILE_TYPE_OR_SIZE_" + path.name)
    if root:
        need(st.st_uid == 0 and not(stat.S_IMODE(st.st_mode) & 0o022),
             "ROOT_FILE_AUTHORITY_" + path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        pre = os.fstat(fd)
        raw = os.read(fd, pre.st_size + 1)
        post = os.fstat(fd)
    finally:
        os.close(fd)
    need(len(raw) == pre.st_size and
         (pre.st_dev, pre.st_ino, pre.st_size, pre.st_mtime_ns) ==
         (post.st_dev, post.st_ino, post.st_size, post.st_mtime_ns),
         "SOURCE_READ_RACE_" + path.name)
    return raw

def trusted_dir(path):
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
         stat.S_IMODE(st.st_mode) == 0o700, "ROOT_TRUST_DIR_" + path.name)

def run(argv, *, stdin=None, timeout=12):
    proc = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False)
    need(proc.returncode == 0, "COMMAND_" + Path(argv[0]).name)
    return proc.stdout

def systemctl(*args):
    return run(["/usr/bin/systemctl", *args])

def show(unit, *fields):
    raw = systemctl("show", unit, "--no-pager", "--property=" + ",".join(fields))
    return dict(s.split("=", 1) for s in raw.decode().splitlines() if "=" in s)

def required_permit(p, phase, now, source_sha):
    fields = {"schema", "purpose", "action", "target", "source_sha",
              "executor_sha256", "dropin_sha256", "original_unit_sha256",
              "postimage_sha256", "witness_sha256", "nonce", "issued_at_unix",
              "expires_at_unix", "financial_authorized"}
    need(type(p) is dict and set(p) == fields, "PERMIT_FIELDS")
    need(p["schema"] == "aoe2war.traffic.pr74.one-use-maintenance.v1" and
         p["purpose"] == PURPOSE and p["action"] == phase and
         p["target"] == str(DROPIN_PATH) and p["source_sha"] == SOURCE_SHA and
         p["executor_sha256"] == source_sha and p["dropin_sha256"] == DROPIN_SHA and
         p["original_unit_sha256"] == ORIGINAL_CAT_SHA and
         p["postimage_sha256"] == EXPECTED_CAT_SHA and
         p["financial_authorized"] is False, "PERMIT_SCOPE_OR_SOURCE")
    need(type(p["nonce"]) is str and re.fullmatch(r"[0-9a-f]{64}", p["nonce"]) is not None,
         "PERMIT_NONCE")
    need(type(p["witness_sha256"]) is str and
         re.fullmatch(r"[0-9a-f]{64}", p["witness_sha256"]) is not None,
         "PERMIT_WITNESS_DIGEST")
    start, end = p["issued_at_unix"], p["expires_at_unix"]
    need(type(start) is int and type(end) is int and
         0 < end-start <= 900 and start-60 <= now < end, "PERMIT_CLOCK_WINDOW")

def verified_permit(phase, now):
    trusted_dir(TRUST)
    trusted_dir(STATE)
    need(sha(DROPIN_BYTES) == DROPIN_SHA, "EMBEDDED_DROPIN_DRIFT")
    need(Path(__file__).resolve() == EXECUTOR and not EXECUTOR.is_symlink(),
         "EXECUTOR_PATH_NOT_ROOT_INSTALLED")
    own = read_single(EXECUTOR, root=True, limit=80000)
    permit = read_single(TRUST / (phase + ".json"), root=True, limit=6000)
    signature = TRUST / (phase + ".sig")
    read_single(signature, root=True, limit=3000)
    read_single(SIGNERS, root=True, limit=3000)
    p = json.loads(permit)
    required_permit(p, phase, now, sha(own))
    need(sha(read_single(WITNESS, root=True, limit=4000)) == p["witness_sha256"],
         "SIGNED_WITNESS_SHA")
    run(["/usr/bin/ssh-keygen", "-Y", "verify",
         "-I", "aoe2war-traffic-pr74-owner", "-n", "aoe2war-traffic-pr74",
         "-f", str(SIGNERS), "-s", str(signature)], stdin=permit)
    return p

def source_footprint(expected_state):
    for path, digest in EXPECTED.items():
        need(sha(read_single(Path(path))) == digest, "SOURCE_DRIFT_" + Path(path).name)
    need(sha(systemctl("cat", "traffic-api.service", "--no-pager")) == API_CAT_SHA,
         "API_INLINE_WRITER_DRIFT")
    need(sha(systemctl("cat", "traffic-ingest.service", "--no-pager")) ==
         (ORIGINAL_CAT_SHA if expected_state == "absent" else EXPECTED_CAT_SHA),
         "INGEST_EFFECTIVE_FINGERPRINT_DRIFT")
    ingest = show("traffic-ingest.service", "DropInPaths", "Environment", "ExecStart",
                  "User", "Group", "PrivateNetwork", "NoNewPrivileges",
                  "ProtectSystem", "NeedDaemonReload", "ActiveState")
    timer = show("traffic-ingest.timer", "ActiveState", "UnitFileState")
    api = show("traffic-api.service", "ActiveState", "Environment")
    steam = show("aoe2war-steam-egress-refresh.service", "Result", "ExecMainStatus")
    web = show("aoe2hdbets-web-prod.service", "ActiveState", "MainPID", "NRestarts")
    need(ingest.get("User") == "tony" and ingest.get("Group") == "tony" and
         ingest.get("PrivateNetwork") == "yes" and
         ingest.get("NoNewPrivileges") == "yes" and
         ingest.get("ProtectSystem") == "strict" and
         ingest.get("NeedDaemonReload") == "no" and
         ingest.get("ActiveState") == "inactive" and
         "/usr/bin/flock -n -E 75" in ingest.get("ExecStart", ""),
         "ORIGINAL_FLOCK_OR_SANDBOX")
    need(timer == {"ActiveState":"active", "UnitFileState":"enabled"},
         "ORIGINAL_TIMER")
    need(api.get("ActiveState") == "active" and
         api.get("Environment") == "TRAFFIC_DISABLE_INLINE_INGEST=1",
         "API_SECOND_WRITER")
    need(steam.get("Result") == "success" and steam.get("ExecMainStatus") == "0",
         "STEAM_V27")
    need(web.get("ActiveState") == "active" and
         web.get("MainPID", "").isdigit() and int(web["MainPID"]) > 100 and
         web.get("NRestarts") == "0", "KINGDOM_WEB")
    if expected_state == "absent":
        need(not DROPIN_PATH.exists() and not DROPIN_PATH.is_symlink() and
             ingest.get("DropInPaths") == "" and
             ingest.get("Environment") == "PYTHONUNBUFFERED=1", "DROPIN_PREIMAGE")
    else:
        need(sha(read_single(DROPIN_PATH, root=True)) == DROPIN_SHA and
             ingest.get("DropInPaths") == str(DROPIN_PATH) and
             set(ingest.get("Environment", "").split()) ==
             {"PYTHONUNBUFFERED=1", "TRAFFIC_INGEST_RECEIPTS_ENABLED=1"},
             "DROPIN_POSTIMAGE")
    ports = run(["/usr/bin/ss", "-H", "-lnt"])
    need(not any(re.search(r":809[2-5](?:\s|$)", ln)
                 for ln in ports.decode().splitlines()), "FINANCIAL_LISTENERS")
    finance = {}
    for unit in ("aoe2hdbets-bet-stake-reconcile.service",
                 "wolochain-mainnet-settlement.service",
                 "wolochain-founder-rewards-settlement.service"):
        props = show(unit, "ActiveState", "UnitFileState")
        need(props.get("ActiveState") in ("inactive", "failed") and
             props.get("UnitFileState") in ("masked", "not-found", "disabled"),
             "FINANCIAL_SERVICE_NOT_HELD")
        finance[unit] = props
    return {"ingest_effective_sha256":
            ORIGINAL_CAT_SHA if expected_state == "absent" else EXPECTED_CAT_SHA,
            "web_pid": int(web["MainPID"]), "timer_state": timer, "financial": finance}

def sqlite_witness():
    db, log = SQLITE.stat(), NGINX.stat()
    conn = sqlite3.connect("file:" + str(SQLITE) + "?mode=ro", uri=True, timeout=2)
    try:
        conn.execute("PRAGMA query_only=ON")
        row = conn.execute("SELECT COALESCE(MAX(rowid),0) FROM traffic_entries").fetchone()[0]
        stamped = conn.execute(
            "SELECT COUNT(*) FROM "
            "(SELECT ingested_at_utc FROM traffic_entries ORDER BY rowid DESC LIMIT 1000) "
            "WHERE ingested_at_utc IS NOT NULL").fetchone()[0]
        cursor = conn.execute(
            "SELECT source_inode,offset FROM traffic_ingest_state WHERE source_path=?",
            (str(NGINX),)).fetchone()
    finally:
        conn.close()
    need(cursor is not None and type(row) is int and row > 0 and type(stamped) is int,
         "SOURCE_CURSOR_OR_SQLITE")
    return {"db_dev":db.st_dev, "db_inode":db.st_ino, "max_rowid":row,
            "old_1000_stamped":stamped, "nginx_dev":log.st_dev,
            "nginx_inode":log.st_ino, "nginx_cursor_inode":int(cursor[0]),
            "nginx_cursor_offset":int(cursor[1])}

def compare_witness(witness, actual, now):
    need(type(witness) is dict and
         set(witness) == set(actual) | {"schema", "observed_at_unix"} and
         witness["schema"] == "aoe2war.traffic.pr74.preinstall-witness.v1" and
         type(witness["observed_at_unix"]) is int and
         0 <= now - witness["observed_at_unix"] <= 90 and
         all(type(witness[k]) is int and witness[k] == v for k,v in actual.items()),
         "WE4_IMMEDIATE_R0_OR_NGINX_CURSOR_DRIFT")

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def consume_nonce(phase, nonce):
    target = STATE / (nonce + ".consumed")
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (phase + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(STATE)

def receipt(phase, nonce, result):
    payload = {"schema":"aoe2war.traffic.pr74.root-postimage.v1", "phase":phase,
               "nonce":nonce, "observed_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
               "result":result, "financial_authorized":False}
    raw = (json.dumps(payload, sort_keys=True, separators=(",",":")) + "\n").encode()
    fd = os.open(STATE / (nonce + "." + phase + ".receipt.json"),
                 os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(STATE)

def exact_install():
    temp = DROPIN_PATH.parent / ("." + DROPIN_PATH.name + ".staged-pr74")
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, DROPIN_BYTES) == len(DROPIN_BYTES), "SHORT_WRITE")
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.link(temp, DROPIN_PATH, follow_symlinks=False)
    os.unlink(temp)
    sync_dir(DROPIN_PATH.parent)
    systemctl("daemon-reload")

def exact_inverse():
    need(sha(read_single(DROPIN_PATH, root=True)) == DROPIN_SHA,
         "INVERSE_REFUSES_DRIFT")
    DROPIN_PATH.unlink()
    sync_dir(DROPIN_PATH.parent)
    systemctl("daemon-reload")

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("install","inverse"), required=True)
    args = parser.parse_args(argv)
    try:
        need(sys.platform == "linux" and os.geteuid() == 0, "EXACT_ROOT_ONLY")
        now = int(time.time())
        permit = verified_permit(args.phase, now)
        lock_fd = os.open(STATE / "executor.lock",
                          os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = source_footprint("absent" if args.phase == "install" else "present")
        witness = json.loads(read_single(WITNESS, root=True, limit=4000))
        physical = sqlite_witness()
        compare_witness(witness, physical, now)
        need(sha(DROPIN_BYTES) == DROPIN_SHA, "DROPIN_INTEGRITY")
        consume_nonce(args.phase, permit["nonce"])
        try:
            if args.phase == "install":
                exact_install()
            else:
                exact_inverse()
            after = source_footprint("present" if args.phase == "install" else "absent")
            need(after["web_pid"] == before["web_pid"], "WEB_PID_CHANGED")
            receipt(args.phase, permit["nonce"],
                    {"pre":before, "post":after, "we4":physical})
        except Exception:
            if args.phase == "install" and DROPIN_PATH.is_file():
                if sha(read_single(DROPIN_PATH, root=True)) == DROPIN_SHA:
                    exact_inverse()
                    need(source_footprint("absent")["web_pid"] == before["web_pid"],
                         "POST_FAILURE_WEB_CHANGED")
            raise
        print(json.dumps({"result":"PASS_ROOT_EXACT_POSTIMAGE",
                          "phase":args.phase, "nonce":permit["nonce"],
                          "receipt_root_private":True}))
        return 0
    except (Hold, OSError, ValueError, TypeError, subprocess.SubprocessError,
            sqlite3.Error) as exc:
        print("HOLD:" + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed required status check for an owner-signed Traffic revocation PR.

Runs only trusted protected BASE code. A proposed PR commit is read as Git
data, never executed. Does not seed trust or create/sign/publish anything.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from scripts.public_audience_v2_revocation_transition import transition

STATE = "ops/traffic-v2-revocation-current.json"
KEY = "ops/traffic-v2-revocation-owner-public.pem"
TRUST = "ops/traffic-v2-revocation-owner-trust.json"
TRUST_SCHEMA = "aoe2war.traffic-v2.revocation-owner-trust.v1"


def hold(reason: str) -> None:
    raise ValueError("TRAFFIC_V2_REVOCATION_REQUIRED_CHECK_HOLD_" + reason)


def git(repo: Path, *args: str, limit: int = 20_000) -> bytes:
    try:
        p = subprocess.run(["git", "-C", str(repo), *args],
                           capture_output=True, timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("TRAFFIC_V2_REVOCATION_REQUIRED_CHECK_HOLD_GIT_UNAVAILABLE") from exc
    if p.returncode or len(p.stdout) > limit:
        hold("GIT_SOURCE_MISSING_OR_TOO_LARGE")
    return p.stdout


def pinned_commit(repo: Path, value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{40,64}", value) is None:
        hold("COMMIT_NOT_FULL_SHA")
    got = git(repo, "rev-parse", "--verify", value + "^{commit}").decode().strip()
    if got != value:
        hold("COMMIT_SHA_DRIFT")
    return value


def regular_blob(repo: Path, commit: str, path: str, limit: int) -> bytes:
    raw = git(repo, "ls-tree", "-z", commit, "--", path)
    if raw.count(b"\0") != 1 or not raw.endswith(b"\0"):
        hold("PROTECTED_FILE_MISSING")
    meta, sep, got = raw[:-1].partition(b"\t")
    if sep != b"\t" or got != path.encode() or not meta.startswith(b"100644 blob "):
        hold("PROTECTED_FILE_NOT_REGULAR_0644")
    blob = git(repo, "show", commit + ":" + path, limit=limit + 1)
    if not 0 < len(blob) <= limit:
        hold("PROTECTED_FILE_OVERSIZED")
    return blob


def strict_json(raw: bytes) -> dict:
    def unique(items):
        out = {}
        for k, v in items:
            if k in out:
                hold("DUPLICATE_JSON_KEY")
            out[k] = v
        return out
    try:
        data = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: hold("NONFINITE_JSON"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("TRAFFIC_V2_REVOCATION_REQUIRED_CHECK_HOLD_INVALID_JSON") from exc
    if type(data) is not dict:
        hold("JSON_NOT_OBJECT")
    return data


def verify(repo: Path, base_sha: str, proposed_sha: str) -> dict:
    """Reject everything except one authentic terminal ACTIVE-to-REVOKED diff."""
    base = pinned_commit(repo, base_sha)
    head = pinned_commit(repo, proposed_sha)
    if base == head:
        hold("NO_STATE_CHANGE")
    changed = git(repo, "diff", "--name-status", "-z", "--no-renames", base, head)
    if changed != b"M\0" + STATE.encode() + b"\0":
        hold("UNREVIEWED_PR_PATH_CHANGES")
    trust = strict_json(regular_blob(repo, base, TRUST, 2000))
    if (set(trust) != {"schema", "owner_public_key_sha256"}
            or trust["schema"] != TRUST_SCHEMA
            or type(trust["owner_public_key_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", trust["owner_public_key_sha256"]) is None):
        hold("INDEPENDENT_OWNER_TRUST_NOT_PINNED")
    pub = regular_blob(repo, base, KEY, 2000)
    if hashlib.sha256(pub).hexdigest() != trust["owner_public_key_sha256"]:
        hold("OWNER_PUBLIC_KEY_HASH_DRIFT")
    old = strict_json(regular_blob(repo, base, STATE, 14000))
    new = strict_json(regular_blob(repo, head, STATE, 14000))
    result = transition(old, new, owner_public_key=pub,
                        trusted_owner_sha256=trust["owner_public_key_sha256"])
    if result.get("status") != "SIGNED_TERMINAL_REVOCATION_TRANSITION_ACCEPTABLE":
        hold("TRANSITION_REFUSED")
    return {
        "status": "SIGNED_MONOTONIC_TRANSITION_REQUIRED_CHECK_PASS",
        "base_sha": base, "proposed_sha": head,
        "new_revision": result["new_revision"],
        "new_state_sha256": result["new_state_sha256"],
        "production_authority_admitted": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--base-sha", required=True)
    ap.add_argument("--proposed-sha", required=True)
    args = ap.parse_args()
    try:
        print(json.dumps(verify(args.repo.resolve(), args.base_sha, args.proposed_sha),
                         sort_keys=True))
        return 0
    except (ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": str(exc), "required_check_passed": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Private V3 dependency materialization companion; no publication or signatures.

A continuity receipt must come from a separately reviewed source-owned freeze
or complete mutation history. This module validates its binding, not its origin.
Never treat matching endpoint snapshots as proof of continuity.
"""
from __future__ import annotations
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Callable

from app.services.traffic import known_visitors, geo
from app.services.traffic.persistence import _non_browser_chain_firehose_sql
from scripts import public_audience_v3_source_prepare as source
from scripts import rebuild_public_audience_archive as canonical

SCHEMA = "traffic.public-audience.v3.dependency-continuity.v1"
FIRST = date(2026, 11, 25)
FIELDS = {"schema","day","effective_from_utc","verified_through_utc",
          "recorded_at_utc","baseline_receipt_sha256","cutoff_receipt_sha256",
          "registry_sha256","geo_sha256","runtime_manifest_sha256",
          "source_commit_sha","source_authority_evidence_sha256","method"}


def require(ok, why):
    if not ok:
        raise ValueError("V3_DEPENDENCY_HOLD_"+why)


def read_pinned(path: Path, pin: str, *, max_bytes: int):
    # Private scope and inode stability on every input; no ambient fallback.
    import os, stat
    require(path.is_absolute() and path.resolve()==path and source.hex64(pin), "PATH_PIN")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        a=os.fstat(fd)
        require(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==os.getuid()
                and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=max_bytes,"FILE_SCOPE")
        with os.fdopen(os.dup(fd),"rb") as f:
            data=f.read(max_bytes+1)
        b=os.fstat(fd)
        require(len(data)==a.st_size and (a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==
                (b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and
                path.stat().st_ino==a.st_ino and hashlib.sha256(data).hexdigest()==pin,"FILE_DRIFT")
        return data
    finally:
        os.close(fd)


def validate_continuity(day: date, receipt: dict, *, expected_sha256: str,
                        now: datetime, source_commit: str):
    require(type(day) is date and day>=FIRST and now.tzinfo is not None
            and now.utcoffset()==timedelta(0),"DAY_SCOPE")
    require(type(receipt) is dict and set(receipt)==FIELDS and receipt["schema"]==SCHEMA
            and receipt["day"]==day.isoformat() and source.sha(receipt)==expected_sha256,
            "CONTINUITY_PREIMAGE")
    require(receipt["source_commit_sha"]==source_commit
            and len(source_commit)==40 and all(c in "0123456789abcdef" for c in source_commit),
            "SOURCE_COMMIT")
    require(all(source.hex64(receipt[k]) for k in FIELDS if k.endswith("_sha256")),
            "EVIDENCE_PINS")
    require(receipt["method"] in ("source-owned-effective-freeze","complete-source-mutation-history"),
            "CONTINUITY_METHOD")
    s=datetime.combine(day,datetime.min.time(),tzinfo=timezone.utc)
    e=s+timedelta(days=1)
    effective,through,recorded=[source.witness.utc_stamp(receipt[k]) for k in
                                ("effective_from_utc","verified_through_utc","recorded_at_utc")]
    require(effective<=s-timedelta(minutes=30) and e<=through<=recorded<=now,
            "BOUNDARY_OR_FUTURE_CLOCK")
    return s,e


def registry_lookup(registry: dict):
    require(type(registry) is dict and set(registry)=={"known_identities","visibility_rules"},
            "REGISTRY_SHAPE")
    ids=registry["known_identities"];visibility=registry["visibility_rules"]
    require(type(ids) is list and type(visibility) is list and len(ids)<=10000
            and len(visibility)<=10000,"REGISTRY_BUDGET")
    lookup=dict(known_visitors._STATIC_KNOWN_VISITORS_BY_IP)
    seen=set()
    for r in ids:
        require(type(r) is dict and r.get("active") in (0,1),"IDENTITY_SHAPE")
        if r["active"] and r["rule_type"]=="ip":
            key=str(r["match_value"]).strip()
            require(key and key not in seen,"AMBIGUOUS_IDENTITY")
            seen.add(key)
            lookup[key]=known_visitors._normalize_identity(r)
    rules=[{**r,"active":bool(r["active"])} for r in visibility if r["active"]]
    rules.sort(key=lambda r:(r["created_at"],r["id"]),reverse=True)
    return lookup,rules


def materialize(raw: sqlite3.Connection, *, day: date, page: dict,
                registry: dict, receipt: dict, continuity_sha256: str,
                source_commit: str, now: datetime,
                frozen_geo: Callable[[str],dict], max_rows: int=200000):
    """Produce exact #84 dependency schema; require already admitted frozen geo
    reader and runtime. The callback must not read mutable live datasets.
    Does not grant finality, verify independent evidence origin, or sign.
    """
    start,end=validate_continuity(day,receipt,expected_sha256=continuity_sha256,
                                  now=now,source_commit=source_commit)
    require(raw.in_transaction and raw.execute("PRAGMA query_only").fetchone()[0]==1,
            "READ_ONLY_SNAPSHOT")
    require(source.sha(registry)==receipt["registry_sha256"],"REGISTRY_DIGEST")
    known,rules=registry_lookup(registry)
    hosts=canonical.project_hosts()
    host_digest=hashlib.sha256(json.dumps(hosts).encode()).hexdigest()
    rule_digest=hashlib.sha256(json.dumps(rules,sort_keys=True,default=str).encode()).hexdigest()
    policy=source.sha({"hosts":hosts,"hosts_sha256":host_digest,"rules_sha256":rule_digest})
    require(set(page)==source.witness.STATE_FIELDS and page["day"]==day.isoformat()
            and page["source_prefix_exhausted"] is True and
            page["missing_receipts"]==page["invalid_clocks"]==0 and
            page["host_rules_sha256"]==policy,"PAGE_BINDING")
    prefix=page["snapshot_rowid"]
    require(type(prefix) is int and prefix>0 and prefix==page["forward_prefix_rowid"]
            and 1<=max_rows<=200000,"PREFIX_OR_BUDGET")
    sql=f"""FROM traffic_entries INDEXED BY idx_traffic_entries_timestamp_line_offset
            WHERE timestamp>=? AND timestamp<? AND host IN ({','.join('?' for _ in hosts)})
              AND ({_non_browser_chain_firehose_sql()})"""
    args=(start.isoformat(),end.isoformat(),*hosts)
    deadline=time.monotonic()+35
    raw.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
    try:
        require(raw.execute("SELECT rowid "+sql+" AND rowid>? LIMIT 1",(*args,prefix)).fetchone() is None,
                "LATE_ROW")
        ips=set();count=0
        for r in raw.execute("SELECT rowid AS source_rowid,event_id,timestamp,ip,line_offset,raw_path,"
                "normalized_path,referrer_host,ua,host,ingested_at_utc "+sql+
                " AND rowid<=? ORDER BY timestamp,line_offset,rowid LIMIT ?",(*args,prefix,max_rows+1)):
            count+=1
            require(count<=max_rows and time.monotonic()<deadline,"ROW_BUDGET")
            t=source.witness.utc_stamp(r["timestamp"]);received=source.witness.utc_stamp(r["ingested_at_utc"])
            require(start<=t<end and t<=received<=now,"INSERTION_CLOCK")
            event=canonical.normalize_row(r,rules=rules)
            if event is not None:ips.add(event["ip"])
        require(count==page["total_rows"],"PAGE_ROW_COUNT")
        result=dict(schema=source.DEPENDENCY_SCHEMA,day=day.isoformat(),as_of_utc=end.isoformat(),
                    source_commit_sha=source_commit,runtime_manifest_sha256=receipt["runtime_manifest_sha256"],
                    geo_dataset_sha256=receipt["geo_sha256"],identity_snapshot_sha256=receipt["registry_sha256"],
                    host_rules_sha256=policy,hosts=hosts,rules=rules,
                    geo_by_ip={},known_by_ip={})
        for ip in sorted(ips):
            require(time.monotonic()<deadline,"LOOKUP_BUDGET")
            g=frozen_geo(ip)
            require(type(g) is dict and set(g)=={"country","country_code","area","city","geo_resolved"}
                    and type(g["geo_resolved"]) is bool,"GEO_SHAPE")
            result["geo_by_ip"][ip]=g
            result["known_by_ip"][ip]=known.get((ip or "").strip())
        require(len(source.witness.canonical(result))<=32_000_000,"PREIMAGE_SIZE")
        return result
    finally:
        raw.set_progress_handler(None,0)


def strict_geo(reader, ip: str):
    """Original GeoIP mapping without swallowing unexpected runtime errors."""
    if ip in geo.DEV_GEO_OVERRIDES:
        return {**geo.DEV_GEO_OVERRIDES[ip],"geo_resolved":True}
    require(reader is not None,"GEO_READER_UNAVAILABLE")
    try:
        r=reader.city(ip)
    except (geo.AddressNotFoundError,ValueError):
        return {"country":"Unknown","country_code":"","area":"","city":"","geo_resolved":False}
    country=r.country.name or r.registered_country.name or r.country.iso_code or r.registered_country.iso_code or "??"
    area=""
    if r.subdivisions and r.subdivisions.most_specific:
        area=r.subdivisions.most_specific.name or r.subdivisions.most_specific.iso_code or ""
    return {"country":country,"country_code":r.country.iso_code or r.registered_country.iso_code or "",
            "area":area,"city":r.city.name or "","geo_resolved":True}

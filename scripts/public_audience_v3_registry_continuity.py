"""Prospective registry mutation witness, source review only.

Never certifies a day. SQLite owner can alter schema/history; a separate source
review must establish writer custody and schema continuity. A mutation means
HOLD (not reconstruction). No identity values copied to the mutation ledger.
No CLI or automatic native installation.
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

TABLES = ("traffic_known_identities", "traffic_visibility_rules")
LEDGER = "traffic_v3_registry_mutation_witness"
SCHEMA = f"CREATE TABLE {LEDGER} (sequence INTEGER PRIMARY KEY AUTOINCREMENT, registry TEXT NOT NULL CHECK(registry IN ('traffic_known_identities','traffic_visibility_rules')), operation TEXT NOT NULL CHECK(operation IN ('INSERT','UPDATE','DELETE')))"
TRIGGERS = {f"v3_registry_witness_{table}_{op.lower()}":
    f"CREATE TRIGGER v3_registry_witness_{table}_{op.lower()} AFTER {op} ON {table} BEGIN INSERT INTO {LEDGER}(registry,operation) VALUES ('{table}','{op}'); END"
    for table in TABLES for op in ("INSERT", "UPDATE", "DELETE")}
TRIGGERS.update({f"v3_registry_witness_ledger_{op.lower()}":
    f"CREATE TRIGGER v3_registry_witness_ledger_{op.lower()} BEFORE {op} ON {LEDGER} BEGIN SELECT RAISE(ABORT,'registry witness append only'); END"
    for op in ("UPDATE", "DELETE")})


def need(ok, why):
    if not ok:
        raise ValueError("REGISTRY_CONTINUITY_HOLD_" + why)


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def schema_objects(db):
    return dict(db.execute("SELECT name,sql FROM sqlite_master WHERE name IN (?,?) OR name=? OR name LIKE 'v3_registry_witness_%' ORDER BY name", (*TABLES,LEDGER)))


def snapshot(db):
    need(db.in_transaction, "TRANSACTION_REQUIRED")
    obj = schema_objects(db)
    need(set(obj) == set(TABLES) | {LEDGER} | set(TRIGGERS), "SCHEMA_SCOPE")
    need(obj[LEDGER] == SCHEMA and all(obj[k] == v for k,v in TRIGGERS.items()), "SCHEMA_DRIFT")
    result = {}
    for table in TABLES:
        cursor = db.execute(f"SELECT * FROM {table} ORDER BY id LIMIT 10001")
        rows = [dict(zip([x[0] for x in cursor.description], row)) for row in cursor]
        need(len(rows) <= 10000, "REGISTRY_BUDGET")
        result[table] = {"count": len(rows), "sha256": sha(rows)}
    count, maximum = db.execute(f"SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM {LEDGER}").fetchone()
    # AUTOINCREMENT also detects a vanished tail under ordinary SQL use.
    seq = db.execute("SELECT seq FROM sqlite_sequence WHERE name=?",(LEDGER,)).fetchone()
    sequence = seq[0] if seq else 0
    need(count == maximum == sequence, "LEDGER_GAP")
    return {"schema_sha256":sha(obj),"schema_version":db.execute("PRAGMA schema_version").fetchone()[0],"registries":result,"mutation_count":count,"sequence":sequence}


def install_in_transaction(db, expected_table_sha):
    """Caller owns a short BEGIN IMMEDIATE transaction and its rollback.
    Only reviewed table DDL and no preexisting witness objects are accepted."""
    need(db.in_transaction, "TRANSACTION_REQUIRED")
    need(db.execute("PRAGMA query_only").fetchone()[0] == 0, "WRITER_REQUIRED")
    obj = schema_objects(db)
    need(set(obj)==set(TABLES), "EXISTING_OBJECTS")
    need(set(expected_table_sha)==set(TABLES) and all(hashlib.sha256(obj[t].encode()).hexdigest()==expected_table_sha[t] for t in TABLES), "SOURCE_SCHEMA_DRIFT")
    need(not db.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name IN (?,?)", TABLES).fetchone(), "EXISTING_REGISTRY_TRIGGER")
    db.execute(SCHEMA)
    for sql in TRIGGERS.values(): db.execute(sql)
    start=snapshot(db)
    need(start["mutation_count"]==0,"NONEMPTY_WITNESS")
    return start


def compare(start, end, *, day, baseline_utc, cutoff_utc, now):
    """Necessary zero-mutation evidence; NOT a continuity attestation."""
    from datetime import date
    d=date.fromisoformat(day);need(d.isoformat()==day and day>="2026-11-25","DAY")
    a=datetime.combine(d,datetime.min.time(),tzinfo=timezone.utc)
    need(all(x.tzinfo is not None and x.utcoffset()==timedelta(0) for x in (baseline_utc,cutoff_utc,now)),"UTC")
    need(baseline_utc<=a-timedelta(minutes=30) and a+timedelta(days=1)<=cutoff_utc<=now,"CLOCK")
    need(start==end,"REGISTRY_OR_SCHEMA_OR_LEDGER_MUTATED")
    return {"status":"ZERO_REGISTRY_MUTATIONS_OBSERVED_REVIEW_REQUIRED","day":day,"baseline_sha256":sha(start),"cutoff_sha256":sha(end),"independent_source_authority_verified":False,"production_certified":False,"publication_authorized":False}

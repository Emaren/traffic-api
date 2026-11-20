"""WE4 bounded publisher runner: real SQLite, owner/file/systemd contracts.

All keys are TEST-ONLY disposable Ed25519 keys; no HEL1 connection, root
config, real source log or actual public day is written.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts import public_audience_v2_runner as runner
from scripts import public_audience_v2_day_admission as witness
from scripts import public_audience_v2_daily_append as publisher
from scripts.public_audience_v2_release_manifest import days_between, sha as matrix_sha
from tests.test_public_audience_v2_day_admission import TwoWitnessDayTests
from tests.test_public_audience_v2_operator_permit import OwnerPermitSignatureTests

NOW = datetime(2026,11,18,14,15,tzinfo=timezone.utc)
SOURCE = "a"*40


class BoundedRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TwoWitnessDayTests.setUpClass()
        OwnerPermitSignatureTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        TwoWitnessDayTests.tearDownClass()
        OwnerPermitSignatureTests.tearDownClass()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="traffic-v2-real-runner-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(os.path.realpath(self.tmp.name))
        self.uid = os.getuid()
        self.dbpath = self.root/"traffic.sqlite"
        self.db = sqlite3.connect(self.dbpath)
        self.addCleanup(self.db.close)
        self.db.executescript("""
        CREATE TABLE traffic_public_daily_audience_rollups (
          project_slug TEXT NOT NULL,bucket_day TEXT NOT NULL,
          total_traffic INTEGER NOT NULL,suspected_human INTEGER NOT NULL,
          confirmed_human INTEGER NOT NULL,updated_at TEXT NOT NULL,
          PRIMARY KEY(project_slug,bucket_day)
        );
        CREATE TABLE traffic_entries(
         event_id TEXT PRIMARY KEY,
         timestamp TEXT NOT NULL,line_offset INTEGER NOT NULL,
         ingested_at_utc TEXT
        );
        CREATE INDEX idx_traffic_entries_timestamp_line_offset
         ON traffic_entries(timestamp,line_offset);
        """+publisher.DAY_CERT_TABLE_SCHEMA)
        self.history={}
        for i,day in enumerate(days_between(date(2026,6,11),date(2026,10,20))):
            v=[5000+i,1200+i,600+i]
            self.history[day]=v
            self.db.execute(
                "INSERT INTO traffic_public_daily_audience_rollups VALUES (?,?,?,?,?,?)",
                ("aoe2hdbets",day,*v,"2026-10-20T21:36:55+00:00"),
            )
        self.original_sha=matrix_sha(self.history)
        # Signed completed prefix 44,247,580 already observed; the DB
        # can have later natural events in another day, not a late Nov17.
        self.db.execute(
            "INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc) "
            "VALUES(?,?,?,?,?)",
            (44_247_600,"fictional-next-day","2026-11-18T12:00:00+00:00",
             12,"2026-11-18T12:02:00+00:00"),
        )
        self.db.commit()
        for key in ("evidence","backup","checkpoint"):
            (self.root/key).mkdir(mode=0o700)
            (self.root/key).chmod(0o700)
        (self.root/"checkpoint"/".canary.lock").write_bytes(b"fixture lock\n")
        (self.root/"checkpoint"/".canary.lock").chmod(0o600)
        self.unit_bytes=b"WE2-repaired-traffic-ingest.service\n"
        self.api=self.root/"app-main.py"
        self.api.write_bytes(b"THE APPROVED FICTIONAL API SOURCE\n")
        self.api.chmod(0o600)
        self.render=self.root/"website-gap-readback.json"
        self.websha="3"*64
        self._write(self.render,{
            "schema":"aoe2war.traffic-v2.gap-renderer-readback.v1",
            "status":"WE2_ACTIVATED_GAP_RENDERER_READBACK",
            "renderer_sha256":self.websha,
            "approved_source_commit":SOURCE,
        })
        source_stat=self.dbpath.stat()
        trust=[]
        for index,raw in enumerate([
            TwoWitnessDayTests.keys[0][1],
            TwoWitnessDayTests.keys[1][1],
            OwnerPermitSignatureTests.key,
        ]):
            p=self.root/("role-%d.pem"%index)
            p.write_bytes(raw);p.chmod(0o600)
            trust.append((str(p),hashlib.sha256(raw).hexdigest()))
        self.cfg={
            "schema":runner.SCHEMA,"project":"aoe2hdbets",
            "source_database":str(self.dbpath),
            "source_dev":source_stat.st_dev,"source_inode":source_stat.st_ino,
            "evidence_dir":str(self.root/"evidence"),
            "backup_dir":str(self.root/"backup"),
            "checkpoint_dir":str(self.root/"checkpoint"),
            "worker_lock":str(self.root/"checkpoint"/".canary.lock"),
            "upstream_key":trust[0][0],"upstream_key_sha256":trust[0][1],
            "classifier_key":trust[1][0],"classifier_key_sha256":trust[1][1],
            "operator_key":trust[2][0],"operator_key_sha256":trust[2][1],
            "source_commit_sha":SOURCE,
            "traffic_api_file":str(self.api),
            "traffic_api_sha256":runner.sha(self.api.read_bytes()),
            "website_gap_receipt":str(self.render),
            "website_gap_renderer_sha256":self.websha,
            "ingest_unit_sha256":runner.sha(self.unit_bytes),
            "max_days_per_run":3,"run_uid":self.uid,"run_gid":os.getgid(),
            "authorization_mode":"one_day",
            "external_revocation_mode":"github-protected-revocation-branch-v1",
            "daily_delegation":str(self.root/"daily-delegation.json"),
            "delegation_state":str(self.root/"delegation-state.json"),
        }
        self.config=self.root/"runner.json"
        self._write(self.config,self.cfg)
        self.upstream=TwoWitnessDayTests()
        self.operator=OwnerPermitSignatureTests()

    def _write(self,path,data):
        path.write_bytes(json.dumps(data,separators=(",",":"),sort_keys=True).encode())
        path.chmod(0o600)

    def now_matrix(self):
        rows=publisher.public_rows(self.db)
        return matrix_sha({r["day"]:[r["total"],r["potential"],r["confirmed"]]
                          for r in rows})

    def set_day(self,day):
        dest=self.root/"evidence"/day
        dest.mkdir(mode=0o700);dest.chmod(0o700)
        page=self.upstream.page(day)
        cert=self.upstream.certificate(page,day)
        cert["historical_release_sha256"]=self.original_sha
        envelope=self.upstream.envelope(cert)
        op=self.operator.payload()
        op.update({
            "day":day,"source_commit_sha":SOURCE,
            "source_database_dev":self.cfg["source_dev"],
            "source_database_ino":self.cfg["source_inode"],
            "certificate_sha256":runner.sha(witness.canonical(cert)),
            "public_preimage_sha256":self.now_matrix(),
            "ingest_service_loaded_sha256":self.cfg["ingest_unit_sha256"],
            "traffic_api_source_sha256":self.cfg["traffic_api_sha256"],
            "website_gap_renderer_sha256":self.cfg["website_gap_renderer_sha256"],
        })
        permit=self.operator.signed(op)
        self._write(dest/"day-envelope.json",envelope)
        self._write(dest/"page-state.json",page)
        self._write(dest/"owner-permit.json",permit)
        return dest

    def service(self,enabled=True):
        return {
            "unit_bytes":self.unit_bytes,
            "loaded_environment":("PYTHONUNBUFFERED=1 "
                + ("TRAFFIC_INGEST_RECEIPTS_ENABLED=1" if enabled else "")),
            "timer_active":True,
        }

    def execute(self,enabled=True):
        cfg=runner.config_read(self.config,uid=self.uid)
        def remote_state(*,now):
            if hasattr(self,"remote_state_override"):
                return self.remote_state_override
            file = Path(self.cfg["delegation_state"])
            return json.loads(file.read_text()) if file.is_file() else None
        with patch.object(publisher,"RELEASE_SHA",self.original_sha), \
             patch.object(witness,"RELEASE_SHA",self.original_sha), \
             patch.object(runner.external,"current_external_state",side_effect=remote_state):
            return runner.run_bounded(
                cfg,now=NOW,uid=self.uid,
                systemd_observer=lambda:self.service(enabled=enabled),
            )

    def test_no_signed_days_is_explicit_hold_no_public_mutation(self):
        old=self.now_matrix()
        r=self.execute()
        self.assertEqual(r["new_count"],0)
        self.assertEqual(r["status"],"HOLD_NO_ADMITTED_COMPLETED_DAY_WITNESS")
        self.assertEqual(self.now_matrix(),old)
        self.assertEqual(r["last_published_day"],"2026-10-19")

    def test_authentic_fictional_day_commits_once_with_real_receipt_file(self):
        self.set_day("2026-11-17")
        out=self.execute()
        self.assertEqual(out["new_count"],1)
        self.assertEqual(out["last_published_day"],"2026-11-17")
        self.assertEqual(len(publisher.public_rows(self.db)),132)
        self.assertEqual(
            len(list((self.root/"backup").glob("traffic-v2-prior-*.json"))),1)
        self.assertEqual(
            len(list((self.root/"checkpoint").glob("completed-*.json"))),1)
        self.assertEqual(self.execute()["new_count"],0)

    def test_two_sequential_fixture_days_and_sqlite_restart_catchup(self):
        self.set_day("2026-11-16")
        first=self.execute()
        self.assertEqual(first["new_count"],1)
        self.db.close();self.db=sqlite3.connect(self.dbpath)
        self.set_day("2026-11-17")
        second=self.execute()
        self.assertEqual(second["new_count"],1)
        self.assertEqual(second["last_published_day"],"2026-11-17")
        self.assertEqual(len(publisher.public_rows(self.db)),133)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM traffic_public_audience_day_certificates_v2"
        ).fetchone()[0],2)
        self.assertEqual(len(list((self.root/"backup").glob("*.json"))),2)
        self.assertEqual(len(list((self.root/"checkpoint").glob("completed-*.json"))),2)

    def test_no_receipt_setting_blocks_before_any_write(self):
        self.set_day("2026-11-17")
        old=self.now_matrix()
        with self.assertRaisesRegex(ValueError,"NATURAL_INSERT_RECEIPT_SETTING_NOT_INSTALLED"):
            self.execute(enabled=False)
        self.assertEqual(self.now_matrix(),old)


    def test_new_after_midnight_arrival_changes_previous_day_session_boundary(self):
        # A page-time late arrival just after midnight is still relevant
        # to a session assigned to the PREVIOUS completed UTC day.
        self.set_day("2026-11-17")
        self.db.execute(
            "INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc)"
            "VALUES(?,?,?,?,?)",
            (44_247_601,"late-nextday-wing",
             "2026-11-18T00:17:00+00:00",
             334,"2026-11-18T13:59:00+00:00"))
        self.db.commit()
        with self.assertRaisesRegex(ValueError,"BACKDATED_LATE_ARRIVAL"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_previous_utc_day_boundary_arrival_refused(self):
        self.set_day("2026-11-17")
        self.db.execute(
            "INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc)"
            "VALUES(?,?,?,?,?)",
            (44_247_601,"late-prior-day-wing",
             "2026-11-16T23:48:00+00:00",
             335,"2026-11-18T13:59:00+00:00"))
        self.db.commit()
        with self.assertRaisesRegex(ValueError,"BACKDATED_LATE_ARRIVAL"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_real_late_insert_with_post_prefix_rowid_rejects_day(self):
        self.set_day("2026-11-17")
        self.db.execute(
            "INSERT INTO traffic_entries(rowid,event_id,timestamp,line_offset,ingested_at_utc)"
            "VALUES(?,?,?,?,?)",
            (44_247_601,"late-fictional","2026-11-17T23:58:00+00:00",
             333,"2026-11-18T13:50:00+00:00"))
        self.db.commit()
        with self.assertRaisesRegex(ValueError,"BACKDATED_LATE_ARRIVAL"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_crash_after_durable_preimage_before_commit_reuses_exact_backup(self):
        self.set_day("2026-11-17")
        self.db.executescript("""
        CREATE TRIGGER deny_signed_day BEFORE INSERT
        ON traffic_public_audience_day_certificates_v2
        BEGIN SELECT RAISE(ABORT,'SIMULATED_CRASH'); END;
        """)
        with self.assertRaisesRegex(sqlite3.IntegrityError,"SIMULATED_CRASH"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)
        self.assertEqual(len(list((self.root/"backup").glob("*.json"))),1)
        self.db.execute("DROP TRIGGER deny_signed_day")
        self.db.commit()
        out=self.execute()
        self.assertEqual(out["new_count"],1)
        self.assertEqual(len(list((self.root/"backup").glob("*.json"))),1)

    def test_root_config_keys_and_wrong_site_readback_fail_closed(self):
        self.set_day("2026-11-17")
        self.render.chmod(0o644)
        with self.assertRaisesRegex(ValueError,"PRIVATE_FILE_OWNER_MODE"):
            self.execute()
        self.render.chmod(0o600)
        self.cfg["traffic_api_sha256"]="0"*64
        self._write(self.config,self.cfg)
        with self.assertRaisesRegex(ValueError,"TRAFFIC_API_SOURCE_DRIFT"):
            self.execute()

    def test_timestamped_current_day_not_offered_for_publication(self):
        (self.root/"evidence"/"2026-11-18").mkdir(mode=0o700)
        r=self.execute()
        self.assertEqual(r["new_count"],0)
        self.assertEqual(r["last_published_day"],"2026-10-19")

    def test_stale_forged_certificate_envelope_rejected(self):
        folder=self.set_day("2026-11-17")
        file=folder/"day-envelope.json"
        raw=json.loads(file.read_text())
        raw["certificate"]["total"]=9999
        self._write(file,raw)
        with self.assertRaisesRegex(ValueError,"OPERATOR_SOURCE_SITE_OR_DB_IDENTITY_DRIFT"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_file_mode_and_symlink_deny_source_artifacts(self):
        folder=self.set_day("2026-11-17")
        f=folder/"page-state.json"
        f.chmod(0o644)
        with self.assertRaisesRegex(ValueError,"PRIVATE_FILE_OWNER_MODE"):
            self.execute()
        f.chmod(0o600)
        new=folder/"page-copy.json"
        f.rename(new)
        f.symlink_to(new)
        with self.assertRaisesRegex(ValueError,"PRIVATE_FILE_PATH_ALIAS"):
            self.execute()


    def test_after_commit_checkpoint_failure_recovers_via_signed_ledger(self):
        self.set_day("2026-11-17")
        with patch.object(runner,"checkpoint_receipt",
                          side_effect=RuntimeError("CRASH_AFTER_DB_COMMIT")):
            with self.assertRaisesRegex(RuntimeError, "CRASH_AFTER_DB_COMMIT"):
                self.execute()
        # Despite a lost process and absent sidecar, SQLite committed the
        # day AND certificate atomically. Restart must not re-insert.
        self.assertEqual(len(publisher.public_rows(self.db)),132)
        self.assertEqual(len(list((self.root/"checkpoint").glob("completed-*.json"))),0)
        replay=self.execute()
        self.assertEqual(replay["new_count"],0)
        self.assertEqual(replay["reconciled_checkpoint_receipts"][
            "recovered_missing_receipts"],["2026-11-17"])
        self.assertEqual(len(list((self.root/"checkpoint").glob("completed-*.json"))),1)
        self.assertEqual(len(publisher.public_rows(self.db)),132)

    def test_unverifiable_gaps_stay_unknown_even_after_latest_signed_day(self):
        self.set_day("2026-11-17")
        published=self.execute()
        self.assertEqual(published["last_published_day"],"2026-11-17")
        self.assertEqual(published["uncertified_lag_days"],0)
        self.assertEqual(published["uncertified_gap_count"],28)
        self.assertEqual(published["uncertified_gap_days"][0],"2026-10-20")
        self.assertEqual(published["uncertified_gap_days"][-1],"2026-11-16")

    def test_persisted_certificate_without_original_preimage_holds_restart(self):
        self.set_day("2026-11-17")
        self.execute()
        original=list((self.root/"backup").glob("*.json"))[0]
        original.rename(original.with_suffix(".quarantined"))
        with self.assertRaisesRegex(ValueError,
                                    "CERTIFIED_DAY_PREIMAGE_MISSING_OR_AMBIGUOUS"):
            self.execute()

    def test_original_worker_lock_contention_refuses_publication(self):
        import fcntl
        self.set_day("2026-11-17")
        p=self.root/"checkpoint"/".canary.lock"
        fd=os.open(p, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError,"EXISTING_WORKER_BUSY"):
                self.execute()
            self.assertEqual(len(publisher.public_rows(self.db)),131)
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN)
            os.close(fd)

    def test_root_installer_cannot_choose_another_unpinned_runtime_uid(self):
        self.cfg["run_uid"]=self.uid+1
        self._write(self.config,self.cfg)
        with self.assertRaisesRegex(ValueError,
                                    "DEDICATED_NONROOT_SERVICE_IDENTITY_MISMATCH"):
            self.execute()

    def test_root_config_duplicate_json_keys_are_refused(self):
        self.config.write_bytes(b'{"schema":"one","schema":"two"}')
        self.config.chmod(0o600)
        with self.assertRaisesRegex(ValueError,"DUPLICATE_JSON_KEY"):
            self.execute()


    def set_delegation(self, *, revocation="ACTIVE", override=None,
                       state_override=None):
        """Owner-signs ONCE using disposable test key; not each UTC day."""
        from scripts import public_audience_v2_daily_delegation as delegated
        owner = {
            "schema":delegated.SCHEMA,
            "delegation_id":"7"*64,
            "project":"aoe2hdbets","approved_by":"Emaren",
            "issued_at_utc":"2026-11-18T12:00:00+00:00",
            "expires_at_utc":"2026-12-08T12:00:00+00:00",
            "earliest_utc_day":"2026-11-17",
            "latest_utc_day":"2026-12-07",
            "max_completed_day_age_days":3,
            "max_days_per_run":3,
            "source_commit_sha":SOURCE,
            "source_database_dev":self.cfg["source_dev"],
            "source_database_ino":self.cfg["source_inode"],
            "ingest_service_loaded_sha256":self.cfg["ingest_unit_sha256"],
            "traffic_api_source_sha256":self.cfg["traffic_api_sha256"],
            "website_gap_renderer_sha256":self.cfg["website_gap_renderer_sha256"],
            "upstream_key_sha256":self.cfg["upstream_key_sha256"],
            "classifier_key_sha256":self.cfg["classifier_key_sha256"],
            "historical_release_sha256":publisher.RELEASE_SHA,
            "gap_aware_api_and_chart":True,
            "no_historical_corrections":True,
        }
        owner.update(override or {})
        signed_owner=self.operator.signed(owner)
        scope={"delegation":signed_owner["permit"],
               "signature":signed_owner["signature"]}
        delegation_sha=runner.sha(witness.canonical(owner))
        state={
            "schema":delegated.STATE_SCHEMA,
            "delegation_sha256":delegation_sha,
            "delegation_id":owner["delegation_id"],"status":revocation,
            "revision":1,"effective_at_utc":"2026-11-18T12:00:00+00:00",
        }
        state.update(state_override or {})
        signed_state=self.operator.signed(state)
        self._write(Path(self.cfg["daily_delegation"]),scope)
        self._write(Path(self.cfg["delegation_state"]),{
            "state":signed_state["permit"],
            "signature":signed_state["signature"],
        })
        self.cfg["authorization_mode"]="delegation"
        self._write(self.config,self.cfg)
        return owner

    def test_auto_delegation_sign_once_new_utc_day_without_owner_daily_permits(self):
        self.set_delegation()
        # Existing per-day owner permit is deliberately absent: only
        # signed upstream and classifier daily evidence may advance the day.
        self.set_day("2026-11-17")
        (self.root/"evidence"/"2026-11-17"/"owner-permit.json").unlink()
        r=self.execute()
        self.assertEqual(r["new_count"],1)
        self.assertEqual(r["last_published_day"],"2026-11-17")
        self.assertEqual(self.execute()["new_count"],0)

    def test_one_delegation_publishes_two_consecutive_signed_days_across_restart(self):
        self.set_delegation(override={
            "issued_at_utc":"2026-11-17T12:00:00+00:00",
            "earliest_utc_day":"2026-11-16",
        })
        first = self.set_day("2026-11-16")
        (first/"owner-permit.json").unlink()
        self.assertEqual(self.execute()["new_count"],1)
        self.db.close()
        self.db=sqlite3.connect(self.dbpath)
        second = self.set_day("2026-11-17")
        (second/"owner-permit.json").unlink()
        finish = self.execute()
        self.assertEqual(finish["new_count"],1)
        self.assertEqual(finish["last_published_day"],"2026-11-17")
        self.assertEqual(len(publisher.public_rows(self.db)),133)
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM "
              "traffic_public_audience_day_certificates_v2").fetchone()[0],2)
        self.assertEqual(self.execute()["new_count"],0)

    def test_revoke_signed_delegation_before_day_write(self):
        self.set_delegation(revocation="REVOKED")
        self.set_day("2026-11-17")
        (self.root/"evidence"/"2026-11-17"/"owner-permit.json").unlink()
        with self.assertRaisesRegex(ValueError,"DELEGATION_REVOKED"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_expired_overscoped_or_source_drift_auto_delegation_refuses(self):
        examples=[
            ({"expires_at_utc":"2026-11-18T13:00:00+00:00"}, {},
             "EXPIRED_NOT_YET_ISSUED"),
            ({"source_commit_sha":"0"*40}, {}, "SIGNED_SOURCE_SCOPE_DRIFT"),
            ({"website_gap_renderer_sha256":"0"*64}, {}, "SIGNED_SOURCE_SCOPE_DRIFT"),
            ({"earliest_utc_day":"2026-11-18"}, {},
             "DAY_SUBSTITUTION_OR_HISTORICAL_BACKFILL"),
            ({"max_completed_day_age_days":100}, {},
             "LATE_DAY_NEEDS_SEPARATE_OWNER_APPROVAL"),
            ({"expires_at_utc":"2027-01-02T12:00:00+00:00"}, {},
             "EXPIRED_NOT_YET_ISSUED"),
        ]
        self.set_day("2026-11-17")
        for body,state,reason in examples:
            with self.subTest(reason=reason,body=body):
                self.set_delegation(override=body,state_override=state)
                with self.assertRaisesRegex(ValueError,reason):
                    self.execute()
                self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_changed_revocation_status_without_owner_signature_refused(self):
        self.set_delegation(revocation="REVOKED")
        path=Path(self.cfg["delegation_state"])
        state=json.loads(path.read_text())
        state["state"]["status"]="ACTIVE"
        self._write(path,state)  # signature intentionally left untouched
        self.set_day("2026-11-17")
        with self.assertRaisesRegex(ValueError,"INDEPENDENT_SIGNATURE_REFUSED"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_missing_one_daily_source_signer_blocks_auto_delegation(self):
        self.set_delegation()
        folder=self.set_day("2026-11-17")
        x=json.loads((folder/"day-envelope.json").read_text())
        x["classifier_signature"]="A"*86
        self._write(folder/"day-envelope.json",x)
        with self.assertRaisesRegex(ValueError,"INDEPENDENT_SIGNATURE_REFUSED"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)


    def test_external_revocation_rejects_old_signed_local_active_state(self):
        # WE2 publishes REVOKED to separately governed external branch.
        self.set_delegation(revocation="REVOKED")
        remote = json.loads(Path(self.cfg["delegation_state"]).read_text())
        # A local restorer maliciously reinstates the older correctly signed
        # ACTIVE state. Its Ed25519 validity must NOT be enough to publish.
        self.set_delegation(revocation="ACTIVE")
        self.remote_state_override = remote
        self.set_day("2026-11-17")
        with self.assertRaisesRegex(ValueError,"TRUSTED_EXTERNAL_STATE_CONFLICT"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_remote_revocation_unavailable_refuses_daily_authorization(self):
        self.set_delegation()
        self.set_day("2026-11-17")
        self.remote_state_override = None
        with self.assertRaisesRegex(ValueError,"LOCAL_OR_EXTERNAL_ENVELOPE_DRIFT"):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)

    def test_changed_remote_revision_requires_new_locally_admitted_state(self):
        self.set_delegation(state_override={"revision":2})
        newer = json.loads(Path(self.cfg["delegation_state"]).read_text())
        self.set_delegation(state_override={"revision":1})
        self.remote_state_override = newer
        self.set_day("2026-11-17")
        with self.assertRaisesRegex(ValueError,"TRUSTED_EXTERNAL_STATE_CONFLICT"):
            self.execute()

    def test_no_delegation_mode_fallback_to_unsigned_day(self):
        self.set_delegation()
        self.set_day("2026-11-17")
        Path(self.cfg["delegation_state"]).unlink()
        with self.assertRaises((FileNotFoundError,ValueError)):
            self.execute()
        self.assertEqual(len(publisher.public_rows(self.db)),131)


if __name__=="__main__":
    unittest.main()

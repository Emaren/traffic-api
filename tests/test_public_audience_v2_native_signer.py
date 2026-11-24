"""Native production payload signer: source contract + safe fixture-only tests.

Only macOS compiles and invokes --validate-fixture/negative no-TTY.
Never accesses real Keychain, never signs data, never activates production.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from scripts import public_audience_v2_day_admission as day
from scripts import public_audience_v2_daily_delegation as delegation
from scripts.public_audience_v2_forward_ledger import RELEASE_SHA

ROOT=Path(__file__).resolve().parents[1]
SWIFT=ROOT/"ops/native/traffic_v2_keychain_payload_sign.swift"


def payload(kind: str) -> dict:
    now=datetime.now(timezone.utc)
    d=(now-timedelta(days=1)).date().isoformat()
    clock=(datetime.fromisoformat(d+"T00:00:00+00:00")+
           timedelta(days=1,minutes=31,seconds=5)).isoformat().replace("+00:00","Z")
    h="a"*64
    if kind=="day":
        obj={k:h for k in day.FIELDS}
        obj.update(schema=day.SCHEMA,project_slug="aoe2hdbets",day=d,
                   historical_release_sha256=RELEASE_SHA,
                   source_snapshot_rowid=12345,forward_prefix_rowid=12345,
                   source_rows=100,missing_insertion_receipts=0,invalid_insertion_clocks=0,
                   upstream_log_closed_through_utc=clock,
                   writer_receipts_closed_through_utc=clock,
                   total=100,potential=55,confirmed=20)
        return obj
    if kind=="delegation":
        obj={k:h for k in delegation.DELEGATION_FIELDS}
        obj.update(schema=delegation.SCHEMA,project="aoe2hdbets",approved_by="Emaren",
                   issued_at_utc=(now-timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   expires_at_utc=(now+timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   earliest_utc_day=d,latest_utc_day=d,
                   max_completed_day_age_days=2,max_days_per_run=1,
                   source_commit_sha="e4fb1eab1c730cf4f9b0d2248fdd80157388d55f",
                   source_database_dev=2064,source_database_ino=131074,
                   upstream_key_sha256="28065defa7c9c48ebde916f19a90a82409274f8ce62d8aea94a5cb39b8b743de",
                   classifier_key_sha256="f445fc5a38b34ae11965fd0db1d28636bb86417ba9d6a63d1ae94886c805316b",
                   historical_release_sha256=RELEASE_SHA,
                   gap_aware_api_and_chart=True,no_historical_corrections=True)
        return obj
    if kind=="state":
        obj={k:h for k in delegation.STATE_FIELDS}
        obj.update(schema=delegation.STATE_SCHEMA,delegation_id=h,
                   delegation_sha256=h,status="ACTIVE",revision=1,
                   effective_at_utc=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
        return obj
    raise AssertionError(kind)


class NativeTrafficSigner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.swift=SWIFT.read_text()
        cls.folder=tempfile.TemporaryDirectory(prefix="traffic-v2-native-fixture-")
        cls.addClassCleanup(cls.folder.cleanup)
        cls.binary=Path(cls.folder.name)/"native"
        if platform.system()=="Darwin" and shutil.which("xcrun"):
            run=subprocess.run(["/usr/bin/xcrun","swiftc","-O","-o",str(cls.binary),str(SWIFT)],
                                text=True,capture_output=True,timeout=90)
            if run.returncode:
                raise AssertionError("swiftc failed:\n"+run.stderr[:3000])

    def test_original_keys_only_and_no_credential_export_or_creation(self):
        code=self.swift
        for value in ("aoe2war.traffic-v2.owner-ed25519.v1",
                      "aoe2war.traffic-v2.upstream-ed25519.v1",
                      "aoe2war.traffic-v2.classifier-ed25519.v1",
                      "SecItemCopyMatching", "PUBLIC_IDENTITY_PIN_DRIFT",
                      "PHYSICAL_LOCAL_TERMINAL_REQUIRED",
                      "isTTYIMPOSSIBLE_SHOULD_NOT_BE_PRESENT"):
            if value.startswith("isTTYIMPOSSIBLE"):
                self.assertNotIn(value,code)
            else:
                self.assertIn(value,code)
        self.assertNotIn("SecItemAdd(",code)
        self.assertNotIn("SecItemDelete(",code)
        self.assertNotIn("rawRepresentation.write",code)
        self.assertIn("O_EXCL",code)
        self.assertIn("O_NOFOLLOW",code)
        self.assertIn("ROLE_KIND_DENIED",code)
        self.assertIn("M1_OWNER_CLASSIFIER_ONLY",code)
        self.assertIn("INTEL_UPSTREAM_ONLY",code)

    def check_native(self, role,kind,obj,expect_ok=True,format_canonical=True,sign=False):
        if not self.binary.exists():
            self.skipTest("native execution requires macOS Swift; static checks still run on Linux")
        fp=Path(self.folder.name)/(role+"-"+kind+".json")
        contents=json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False)
        fp.write_text(contents if format_canonical else json.dumps(obj,indent=2))
        sha=hashlib.sha256(fp.read_bytes()).hexdigest()
        cmd=[str(self.binary),"--sign" if sign else "--validate-fixture",
             "--role",role,"--kind",kind,"--input",str(fp)]
        if sign:cmd+=["--signature-output",str(fp)+".sig","--approve-sha256",sha]
        result=subprocess.run(cmd,text=True,capture_output=True,timeout=12)
        self.assertEqual(result.returncode==0,expect_ok,
                         result.stdout+"\n"+result.stderr)
        if sign:self.assertFalse(Path(str(fp)+".sig").exists())
        return result

    def test_three_canonical_schemas_read_only(self):
        self.check_native("upstream","day",payload("day"))
        self.check_native("classifier","day",payload("day"))
        self.check_native("owner","delegation",payload("delegation"))
        self.check_native("owner","state",payload("state"))

    def test_v3_exact_schema_original_roles_and_scope(self):
        obj = payload("day")
        if obj["day"] < "2026-11-23":
            self.skipTest("runtime fixture day precedes V3 epoch")
        obj = {k:v for k,v in obj.items() if k in day.V3_FIELDS}
        obj.update({k:"a"*64 for k in day.V3_FIELDS-set(obj)})
        obj["schema"] = day.V3_SCHEMA
        obj["classifier_source_commit_sha"] = "a"*40
        self.check_native("upstream","day",obj)
        self.check_native("classifier","day",obj)
        self.check_native("owner","day",obj,False)
        bad=dict(obj, schema=day.SCHEMA)
        self.check_native("classifier","day",bad,False)
        bad=dict(obj, total=True)
        self.check_native("classifier","day",bad,False)
        bad=dict(obj, day="2026-11-22")
        self.check_native("classifier","day",bad,False)

    def test_cross_role_and_incomplete_day_denials(self):
        self.check_native("owner","day",payload("day"),False)
        self.check_native("classifier","state",payload("state"),False)
        wrong=payload("day");wrong["invalid_insertion_clocks"]=1
        self.check_native("upstream","day",wrong,False)
        wrong=payload("day");wrong["total"]=4;wrong["confirmed"]=8
        self.check_native("upstream","day",wrong,False)

    def test_unqualified_json_or_placeholder_denied(self):
        self.check_native("owner","state",payload("state"),False,format_canonical=False)
        drift=payload("delegation");drift["upstream_key_sha256"]="0"*64
        self.check_native("owner","delegation",drift,False)
        drift=payload("state");drift["unexpected"]=True
        self.check_native("owner","state",drift,False)

    def test_headless_sign_refused_without_keychain_lookup(self):
        result=self.check_native("owner","state",payload("state"),False,sign=True)
        self.assertIn("PHYSICAL_LOCAL_TERMINAL_REQUIRED",result.stderr)


if __name__=="__main__":
    unittest.main()

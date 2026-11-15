"""Pure exact-preimage/rollback tests; never touches HEL1 systemd."""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
from io import StringIO
import json
from unittest import TestCase
from unittest.mock import patch

from scripts import public_audience_v2_receipt_writer_admission as adm


SERVICE = b"""[Unit]
Description=Traffic
[Service]
User=tony
Group=tony
PrivateNetwork=yes
NoNewPrivileges=yes
ProtectSystem=strict
CapabilityBoundingSet=
ReadWritePaths=/mnt/HC_Volume_105319120/traffic-db /run/traffic-ingest
InaccessiblePaths=-/run/postgresql -/var/run/postgresql
ExecStart=/usr/bin/flock -n -E 75 /run/traffic-ingest/sync.lock /var/www/Traffic/traffic-api/.venv/bin/python3 scripts/sync_traffic_logs.py
"""
TIMER = b"""[Timer]
OnUnitInactiveSec=2min
Unit=traffic-ingest.service
"""
PERSISTENCE = b"""TRAFFIC_INGEST_RECEIPTS_ENABLED ingested_at_utc
strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')
"""
INGEST = b"unmodified real writer command"
STEAM = b"v27 source preimage"
ORIGINAL = b"source root preimage"


class SourceOnlyAdmission(TestCase):
    def test_exact_candidate_is_single_env_variable(self):
        self.assertEqual(
            adm.DROPIN,
            b"[Service]\nEnvironment=TRAFFIC_INGEST_RECEIPTS_ENABLED=1\n",
        )
        self.assertEqual(adm.DROPIN.count(b"\n"), 2)
        self.assertEqual(adm.manifest()["dropin_proposed_sha256"], adm.digest(adm.DROPIN))

    def test_no_permit_no_finance_no_publication(self):
        r=adm.manifest()
        self.assertIsNone(r["approved_by"])
        self.assertFalse(r["install_authorized"])
        self.assertFalse(r["financial_authorized"])
        self.assertFalse(r["systemd_mutation"])
        self.assertFalse(r["sqlite_mutation"])
        self.assertFalse(r["old_null_receipts_backfilled"])
        self.assertFalse(r["public_audience_publication_authorized"])

    def test_inverse_accepts_only_exact_postimage_and_absent_preimage(self):
        result=adm.inverse_decision(
            actual=adm.DROPIN,preimage_absent=True,
            original_service_sha=adm.SERVICE_SHA256,
            original_timer_sha=adm.TIMER_SHA256,
        )
        self.assertEqual(result,adm.ALLOWED_INVERSE)

    def test_inverse_refuses_altered_or_missing_file(self):
        for value in (None,b"",adm.DROPIN+b"Environment=EXTRA=1\n",b"[Service]\n"):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,"DROPIN_POSTIMAGE_DRIFT"):
                adm.inverse_decision(
                    actual=value,preimage_absent=True,
                    original_service_sha=adm.SERVICE_SHA256,
                    original_timer_sha=adm.TIMER_SHA256,
                )

    def test_inverse_refuses_unknown_original_source(self):
        with self.assertRaisesRegex(ValueError,"ORIGINAL_UNIT_PREIMAGE_DRIFT"):
            adm.inverse_decision(actual=adm.DROPIN,preimage_absent=True,
                original_service_sha="00",original_timer_sha=adm.TIMER_SHA256)
        with self.assertRaisesRegex(ValueError,"UNKNOWN_PREEXISTING_DROPIN"):
            adm.inverse_decision(actual=adm.DROPIN,preimage_absent=False,
                original_service_sha=adm.SERVICE_SHA256,
                original_timer_sha=adm.TIMER_SHA256)

    def fixture(self,*,service=SERVICE,timer=TIMER,persistence=PERSISTENCE,ingest=INGEST,
                steam=STEAM,original=ORIGINAL,dropin=False):
        with ExitStack() as stack:
            for field,payload in (
                ("SERVICE_SHA256",SERVICE),("TIMER_SHA256",TIMER),
                ("PERSISTENCE_SHA256",PERSISTENCE),
                ("INGEST_SCRIPT_SHA256",INGEST),
                ("STEAM_V27_SHA256",STEAM),("STEAM_ROOT_PIN_SHA256",ORIGINAL),
            ):
                stack.enter_context(patch.object(adm,field,adm.digest(payload)))
            return adm.validate_unit_preimage(
                service,timer,persistence,ingest,steam,original,
                dropin_preexists=dropin)

    def test_unmodified_exact_source_and_inverse_preimage_matches(self):
        self.assertFalse(self.fixture()["install_authorized"])

    def test_any_source_pin_drift_is_hold(self):
        for name in ("service","timer","persistence","ingest","steam","original"):
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,"EXACT_SOURCE_PIN_DRIFT"):
                self.fixture(**{name:globals()[name.upper()]+b"\nchanged"})

    def test_timer_drift_same_sha_is_still_hold(self):
        # Check that the source text policy, not merely a hash, is inspected.
        wrong=b"[Timer]\nOnUnitInactiveSec=5min\nUnit=traffic-ingest.service\n"
        with patch.object(adm,"TIMER_SHA256",adm.digest(wrong)):
            with ExitStack() as s:
                for field,payload in (
                    ("SERVICE_SHA256",SERVICE),
                    ("PERSISTENCE_SHA256",PERSISTENCE),
                    ("INGEST_SCRIPT_SHA256",INGEST),
                    ("STEAM_V27_SHA256",STEAM),
                    ("STEAM_ROOT_PIN_SHA256",ORIGINAL),
                ):
                    s.enter_context(patch.object(adm,field,adm.digest(payload)))
                with self.assertRaisesRegex(ValueError,"ORIGINAL_TIMER_IDENTITY_DRIFT"):
                    adm.validate_unit_preimage(SERVICE,wrong,PERSISTENCE,INGEST,STEAM,ORIGINAL)

    def test_unknown_existing_dropin_never_overwritten(self):
        with self.assertRaisesRegex(ValueError,"RECEIPT_DROPIN_ALREADY_PRESENT"):
            self.fixture(dropin=True)

    def test_original_single_writer_flap_is_hold(self):
        broken=SERVICE.replace(b"flock -n -E 75",b"python -m alternate")
        with patch.object(adm,"SERVICE_SHA256",adm.digest(broken)):
            with ExitStack() as s:
                for field,payload in (
                    ("TIMER_SHA256",TIMER),("PERSISTENCE_SHA256",PERSISTENCE),
                    ("INGEST_SCRIPT_SHA256",INGEST),("STEAM_V27_SHA256",STEAM),
                    ("STEAM_ROOT_PIN_SHA256",ORIGINAL),
                ):
                    s.enter_context(patch.object(adm,field,adm.digest(payload)))
                with self.assertRaisesRegex(ValueError,"SINGLE_WRITER_FLOCK_COMMAND_DRIFT"):
                    adm.validate_unit_preimage(broken,TIMER,PERSISTENCE,INGEST,STEAM,ORIGINAL)

    def test_cli_outputs_explicit_nonzero_nonpermit(self):
        with patch("sys.argv",["admission","--phase","review-only"]):
            out=StringIO()
            with redirect_stdout(out):
                rc=adm.main()
        result=json.loads(out.getvalue())
        self.assertEqual(rc,2)
        self.assertFalse(result["install_authorized"])
        self.assertIsNone(result["approved_by"])

    def test_api_single_writer_guard_requires_exact_handoff_fingerprint(self):
        fragment=b"[Service]\nUser=tony\n"
        handoff=b"[Service]\nEnvironment=TRAFFIC_DISABLE_INLINE_INGEST=1\n"
        effective=fragment+handoff
        with ExitStack() as stack:
            for field,data in (
                ("TRAFFIC_API_SHA256",fragment),
                ("TRAFFIC_API_INLINE_HANDOFF_SHA256",handoff),
                ("TRAFFIC_API_EFFECTIVE_SHA256",effective),
            ):
                stack.enter_context(patch.object(adm,field,adm.digest(data)))
            adm.check_api_writer_preimage(fragment,handoff,effective)
            with self.assertRaisesRegex(ValueError,"INLINE_INGEST_SOURCE_DRIFT"):
                adm.check_api_writer_preimage(fragment,handoff+b"extra",effective)
            wrong=b"[Service]\nEnvironment=TRAFFIC_DISABLE_INLINE_INGEST=0\n"
            with patch.object(adm,"TRAFFIC_API_INLINE_HANDOFF_SHA256",adm.digest(wrong)):
                with self.assertRaisesRegex(ValueError,"INLINE_INGEST_NOT_PINNED_DISABLED"):
                    adm.check_api_writer_preimage(fragment,wrong,effective)

    def test_physical_inspection_is_linux_root_only(self):
        with patch.object(adm.sys,"platform","darwin"):
            with self.assertRaisesRegex(ValueError,"EXACT_LINUX_ROOT_READONLY"):
                adm.inspect_live_no_mutation()


if __name__ == "__main__":
    import unittest
    unittest.main()

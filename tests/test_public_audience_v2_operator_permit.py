"""Traffic V2 owner permit verification against genuine disposable Ed25519 keys."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import public_audience_v2_day_admission as signed
from scripts import public_audience_v2_operator_permit as permit


NOW = datetime(2026, 11, 18, 14, 0, tzinfo=timezone.utc)
SOURCE = "a" * 40
OLD = "b" * 64
CERT = "c" * 64
UPSTREAM = "d" * 64
CLASSIFIER = "e" * 64
UNIT = "f" * 64
API = "1" * 64
WEB = "2" * 64


class OwnerPermitSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="traffic-v2-operator-")
        cls.folder = Path(cls.temp.name)
        cls.private = cls.folder / "fictional-operator.key"
        public = cls.folder / "fictional-operator.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                        "-out", str(cls.private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private),
                        "-pubout", "-out", str(public)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.key = public.read_bytes()
        cls.sha = hashlib.sha256(cls.key).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def signed(self, payload):
        file = self.folder / "permit.json"
        sig = self.folder / "permit.sig"
        file.write_bytes(signed.canonical(payload))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey",
                        str(self.private), "-rawin", "-in", str(file),
                        "-out", str(sig)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"permit": payload, "signature": base64.urlsafe_b64encode(
            sig.read_bytes()).decode().rstrip("=")}

    def payload(self):
        return {
            "schema": permit.SCHEMA, "project": "aoe2hdbets",
            "day": "2026-11-17",
            "certificate_sha256": CERT, "source_commit_sha": SOURCE,
            "public_preimage_sha256": OLD, "source_database_dev": 120,
            "source_database_ino": 333, "ingest_service_loaded_sha256": UNIT,
            "traffic_api_source_sha256": API,
            "website_gap_renderer_sha256": WEB,
            "expires_at_utc": (NOW + timedelta(minutes=45)).isoformat(),
            "gap_aware_api_and_chart": True,
            "approved_by": "Emaren",
        }

    def verify(self, env, **kwargs):
        params = {
            "trust_public_key": self.key,
            "trusted_public_sha256": self.sha,
            "upstream_key_sha256": UPSTREAM,
            "classifier_key_sha256": CLASSIFIER,
            "reviewed_source_commit_sha": SOURCE,
            "database_dev": 120, "database_ino": 333,
            "reviewed_ingest_unit_sha256": UNIT,
            "reviewed_traffic_api_sha256": API,
            "reviewed_website_gap_renderer_sha256": WEB,
            "expected_public_preimage_sha256": OLD,
            "certificate_sha256": CERT, "now": NOW,
        }
        return permit.verify_operator_permit(env, **{**params, **kwargs})

    def test_separately_pinned_owner_signature_produces_only_verified_scope(self):
        r = self.verify(self.signed(self.payload()))
        self.assertEqual(r["status"], "INDEPENDENT_OPERATOR_PERMIT_VERIFIED")
        self.assertEqual(r["permitted_public_preimage_sha256"], OLD)
        self.assertFalse(r["live_operation_performed"])
        self.assertEqual(r["day"], "2026-11-17")

    def test_forged_signed_payload_and_wrong_keys_refused(self):
        env = self.signed(self.payload())
        env["permit"]["source_database_ino"] = 444
        with self.assertRaisesRegex(ValueError, "OPERATOR_SOURCE_SITE_OR_DB_IDENTITY_DRIFT"):
            self.verify(env)
        env = self.signed(self.payload())
        env["permit"]["approved_by"] = "Emaren"   # unchanged identity
        env["permit"]["day"] = "2026-11-16"        # signature broken
        with self.assertRaisesRegex(ValueError, "INDEPENDENT_SIGNATURE_REFUSED"):
            self.verify(env)
        env = self.signed(self.payload())
        with self.assertRaisesRegex(ValueError, "OPERATOR_ROOT_TRUST_NOT_SEPARATELY_PINNED"):
            self.verify(env, classifier_key_sha256=self.sha)

    def test_expired_or_too_broad_permit_refused(self):
        for minutes in (-1, 61):
            payload = self.payload()
            payload["expires_at_utc"] = (NOW+timedelta(minutes=minutes)).isoformat()
            with self.subTest(minutes=minutes), \
                 self.assertRaisesRegex(ValueError, "OWNER_PERMIT_EXPIRED_OR_TOO_BROAD"):
                self.verify(self.signed(payload))

    def test_site_gap_renderer_source_or_preimage_mismatch_refused(self):
        env = self.signed(self.payload())
        for kwargs in (
            {"reviewed_website_gap_renderer_sha256": "3" * 64},
            {"expected_public_preimage_sha256": "4" * 64},
            {"reviewed_source_commit_sha": "b" * 40},
            {"database_ino": 1000},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(
                ValueError, "OPERATOR_SOURCE_SITE_OR_DB_IDENTITY_DRIFT"
            ):
                self.verify(env, **kwargs)

    def test_anonymous_or_unreviewed_operator_cannot_become_owner(self):
        for field,value in (
            ("approved_by", "someone_else"),
            ("gap_aware_api_and_chart", False),
            ("project", "financial"),
        ):
            payload=self.payload()
            payload[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(
                ValueError,"OPERATOR_SOURCE_SITE_OR_DB_IDENTITY_DRIFT"
            ):
                self.verify(self.signed(payload))


if __name__ == "__main__":
    unittest.main()

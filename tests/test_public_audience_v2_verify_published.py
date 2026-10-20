from __future__ import annotations

import copy
import os
import subprocess
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_verify_published as verify
from scripts import public_audience_v2_atomic_publish as publisher
from scripts import public_audience_v2_release_manifest as manifest


class PublishedAudienceThreeLayerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "site.sqlite3"
        self.candidate = {
            day: [j + 900, j + 50, j + 5]
            for j, day in enumerate(verify.EXPECTED)
        }
        self.digest = manifest.sha(self.candidate)
        with sqlite3.connect(self.path) as db:
            db.execute("""
                CREATE TABLE traffic_public_daily_audience_rollups(
                    project_slug TEXT, bucket_day TEXT,
                    total_traffic INTEGER, suspected_human INTEGER,
                    confirmed_human INTEGER, updated_at TEXT,
                    PRIMARY KEY(project_slug,bucket_day)
                )
            """)
            db.executemany(
                "INSERT INTO traffic_public_daily_audience_rollups VALUES(?,?,?,?,?,?)",
                [(publisher.PROJECT, day, *numbers,
                  "2026-10-20T20:00:00+00:00")
                 for day, numbers in self.candidate.items()]
            )

    def payload(self, frontend=False):
        return {
            "ok": True,
            **(
                {"startDate": "2026-06-11", "coverageEndedAt": "2026-10-19"}
                if frontend else {
                    "project_slug": publisher.PROJECT,
                    "coverage_started_at": "2026-06-11",
                    "coverage_ended_at": "2026-10-19",
                }
            ),
            "points": [
                {
                    "date": day,
                    "calculatedAt": "2026-10-20T20:00:00+00:00",
                    "values": {
                        "totalTraffic": vals[0],
                        "suspectedHuman": vals[1],
                        "confirmedHuman": vals[2],
                    },
                } for day, vals in self.candidate.items()
            ],
        }

    def test_exact_three_layer_131_day_match(self):
        with patch.object(publisher, "EXPECTED_CANDIDATE_SHA", self.digest):
            with patch.object(verify, "fetch_json", side_effect=[
                self.payload(False), self.payload(True)
            ]):
                result = verify.verify(
                    self.path, "http://127.0.0.1:3345/a", "https://aoe2war.com/a"
                )
        self.assertEqual(result["status"], "VERIFIED_PUBLISHED")
        self.assertEqual(result["days"], 131)
        self.assertEqual(result["daily_sha256"], self.digest)

    def test_cloudflare_public_transport_uses_curl_not_python_urllib(self):
        payload = self.payload(True)
        response = subprocess.CompletedProcess(
            args=["curl"], returncode=0,
            stdout=__import__("json").dumps(payload).encode("utf-8"), stderr=b"",
        )
        with patch.object(verify.subprocess, "run", return_value=response) as curl:
            with patch.object(verify, "urlopen",
                              side_effect=AssertionError("urllib must not call Cloudflare")):
                fetched = verify.fetch_json(verify.PUBLIC_AOE2WAR_AUDIENCE_URL)
        with patch.object(publisher, "EXPECTED_CANDIDATE_SHA", self.digest):
            checked = verify.verify_api_points(fetched, frontend=True)
        self.assertEqual(checked, self.candidate)
        arguments = curl.call_args.args[0]
        self.assertEqual(arguments[0], "/usr/bin/curl")
        self.assertIn("--fail", arguments)
        self.assertIn("--max-filesize", arguments)
        self.assertIn("--max-redirs", arguments)
        self.assertEqual(arguments[-1], verify.PUBLIC_AOE2WAR_AUDIENCE_URL)

    def test_cloudflare_403_via_curl_is_not_silently_accepted(self):
        failed = subprocess.CompletedProcess(
            args=["curl"], returncode=22, stdout=b"", stderr=b"HTTP 403",
        )
        with patch.object(verify.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "curl transport failed"):
                verify.fetch_json(verify.PUBLIC_AOE2WAR_AUDIENCE_URL)

    def test_cloudflare_http_200_but_wrong_daily_values_fail_digest(self):
        invalid = self.payload(True)
        invalid["points"][0]["values"]["confirmedHuman"] += 1
        response = subprocess.CompletedProcess(
            args=["curl"], returncode=0,
            stdout=__import__("json").dumps(invalid).encode("utf-8"), stderr=b"",
        )
        with patch.object(verify.subprocess, "run", return_value=response):
            fetched = verify.fetch_json(verify.PUBLIC_AOE2WAR_AUDIENCE_URL)
        with patch.object(publisher, "EXPECTED_CANDIDATE_SHA", self.digest):
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                verify.verify_api_points(fetched, frontend=True)

    def test_redirect_and_body_size_fail_closed(self):
        with patch.object(verify.subprocess, "run", return_value=(
            subprocess.CompletedProcess(args=["curl"], returncode=0,
                stdout=b"x" * (verify.MAX_PUBLIC_JSON_BYTES + 1), stderr=b"")
        )):
            with self.assertRaisesRegex(RuntimeError, "oversized"):
                verify.fetch_json(verify.PUBLIC_AOE2WAR_AUDIENCE_URL)
        with self.assertRaisesRegex(RuntimeError, "unapproved"):
            verify.fetch_json("https://aoe2war.com/traffic")

    def test_frontend_duplicate_and_unverified_current_day_rejected(self):
        payload = self.payload(True)
        payload["points"][0]["date"] = "2026-10-20"
        with patch.object(publisher, "EXPECTED_CANDIDATE_SHA", self.digest):
            with self.assertRaisesRegex(RuntimeError, "unknown or partial"):
                verify.verify_api_points(payload, frontend=True)

    def test_backend_mismatched_utc_archive_coverage_rejected(self):
        payload = self.payload(False)
        payload["coverage_ended_at"] = "2026-10-20"
        with self.assertRaisesRegex(RuntimeError, "coverage mismatch"):
            verify.verify_api_points(payload, frontend=False)

    def test_frontend_stale_cached_response_rejected(self):
        stale = self.payload(True)
        stale["points"].pop()
        with self.assertRaisesRegex(RuntimeError, "point count mismatch"):
            verify.verify_api_points(stale, frontend=True)

    def test_backend_premature_publication_timestamp_rejected(self):
        premature = self.payload(False)
        premature["points"][-1]["calculatedAt"] = "2026-10-19T06:00:00+00:00"
        with self.assertRaisesRegex(RuntimeError, "before UTC day"):
            verify.verify_api_points(premature, frontend=False)


if __name__ == "__main__":
    unittest.main()

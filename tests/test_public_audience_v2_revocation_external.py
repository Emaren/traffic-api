"""Adversarial external GitHub revocation-anchor acceptance: no live network."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
import json
import unittest

from scripts import public_audience_v2_revocation_external as external

NOW = datetime(2026,11,18,17,0,tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, body: bytes, *, date: str, status: int=200,
                 content_type="application/json"):
        self.body=body
        self.status=status
        self.headers={"Date":date,"Content-Type":content_type}
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def read(self,n):
        return self.body[:n]


class RevocationExternalTests(unittest.TestCase):
    def setUp(self):
        self.state={
            "state":{"schema":"traffic.public-audience.v2.delegation-revocation-state.v1",
                     "delegation_sha256":"a"*64,
                     "delegation_id":"b"*64,
                     "status":"ACTIVE","revision":1,
                     "effective_at_utc":"2026-11-18T12:00:00+00:00"},
            "signature":"placeholder-signed-by-separate-owner-in-integration-tests",
        }

    def response(self, state=None, *, path=external.PATH, tamper_hash=False):
        raw=json.dumps(state if state is not None else self.state,
                       sort_keys=True,separators=(",",":")).encode()
        git_sha=hashlib.sha1(
            b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        if tamper_hash:git_sha="f"*40
        obj={"type":"file","path":path,"encoding":"base64",
             "content":base64.b64encode(raw).decode(),
             "size":len(raw),"sha":git_sha}
        return json.dumps(obj).encode()

    def test_live_allowlisted_github_readback_accepts_current_remote_state(self):
        def opener(request,timeout):
            self.assertEqual(request.full_url,external.URL)
            self.assertEqual(request.get_method(),"GET")
            self.assertEqual(timeout,5)
            return FakeResponse(self.response(),date=format_datetime(NOW))
        got=external.current_external_state(now=NOW,opener=opener)
        self.assertEqual(got,self.state)
        external.compare_root_and_external(self.state,got)

    def test_valid_local_old_active_cannot_override_external_revoked(self):
        revoked=json.loads(json.dumps(self.state))
        revoked["state"]["status"]="REVOKED"
        with self.assertRaisesRegex(ValueError,"TRUSTED_EXTERNAL_STATE_CONFLICT"):
            external.compare_root_and_external(self.state,revoked)

    def test_missing_external_readback_fails_closed(self):
        def refused(request,timeout):raise TimeoutError("unreachable")
        with self.assertRaisesRegex(ValueError,"UPSTREAM_UNAVAILABLE"):
            external.current_external_state(now=NOW,opener=refused)

    def test_stale_and_future_http_date_fails_closed(self):
        for minutes in (-121,121):
            with self.subTest(minutes=minutes):
                date=format_datetime(NOW+timedelta(seconds=minutes))
                def opener(request,timeout):
                    return FakeResponse(self.response(),date=date)
                with self.assertRaisesRegex(ValueError,"REMOTE_HTTP_DATE_STALE_OR_FUTURE"):
                    external.current_external_state(now=NOW,opener=opener)

    def test_wrong_remote_branch_path_refused(self):
        with self.assertRaisesRegex(ValueError,"GITHUB_STATE_PATH_OR_SHAPE_DRIFT"):
            external.verify_github_content(
                self.response(path="ops/attacker-state.json"),
                format_datetime(NOW),now=NOW)

    def test_content_hash_and_length_integrity_refused(self):
        with self.assertRaisesRegex(ValueError,"GITHUB_BLOB_IDENTITY_DRIFT"):
            external.verify_github_content(
                self.response(tamper_hash=True),format_datetime(NOW),now=NOW)
        payload=json.loads(self.response())
        payload["size"]+=1
        with self.assertRaisesRegex(ValueError,"GITHUB_CONTENT_SIZE_DRIFT"):
            external.verify_github_content(
                json.dumps(payload).encode(),format_datetime(NOW),now=NOW)

    def test_extra_old_or_missing_local_state_refused(self):
        for obj in (None,{},{"state":self.state["state"]}):
            with self.subTest(obj=obj),self.assertRaisesRegex(
                    ValueError,"LOCAL_OR_EXTERNAL_ENVELOPE_DRIFT"):
                external.compare_root_and_external(obj,self.state)

    def test_no_unauthenticated_redirect_or_html_fallback(self):
        def opener(request,timeout):
            return FakeResponse(self.response(),date=format_datetime(NOW),
                                status=302)
        with self.assertRaisesRegex(ValueError,"GITHUB_HTTP_STATUS_OR_CONTENT_TYPE"):
            external.current_external_state(now=NOW,opener=opener)
        def opener_html(request,timeout):
            return FakeResponse(self.response(),date=format_datetime(NOW),
                                content_type="text/html")
        with self.assertRaisesRegex(ValueError,"GITHUB_HTTP_STATUS_OR_CONTENT_TYPE"):
            external.current_external_state(now=NOW,opener=opener_html)

    def test_duplicate_json_keys_refused(self):
        raw=b'{"type":"file","type":"file"}'
        with self.assertRaisesRegex(ValueError,"DUPLICATE_JSON_KEY"):
            external.verify_github_content(raw,format_datetime(NOW),now=NOW)

    def test_changed_remotely_valid_active_revision_must_match_local(self):
        other=json.loads(json.dumps(self.state))
        other["state"]["revision"]=2
        with self.assertRaisesRegex(ValueError,"TRUSTED_EXTERNAL_STATE_CONFLICT"):
            external.compare_root_and_external(self.state,other)


if __name__=="__main__":
    unittest.main()

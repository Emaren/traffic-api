"""Disposable Git commits + real Ed25519 test signatures; no production trust."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import public_audience_v2_revocation_required_check as check
from tests import test_public_audience_v2_revocation_transition as prior


class RequiredGithubTransitionCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prior.SignedMonotonicRevocationTests.setUpClass()
        cls.signer = prior.SignedMonotonicRevocationTests()
        cls.pub = cls.signer.pub

    @classmethod
    def tearDownClass(cls):
        prior.SignedMonotonicRevocationTests.tearDownClass()

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.repo), *args],
                       capture_output=True, check=True, timeout=8)

    def sha(self):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            timeout=8, text=True).strip()

    def write(self, path, content):
        dst = self.repo / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(content if isinstance(content, bytes) else content.encode())

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "disposable signed-state fixture")
        return self.sha()

    def state(self, revision=1, status="ACTIVE"):
        return self.signer.state(
            revision=revision, status=status,
            time="2026-11-18T12:00:00+00:00" if revision == 1
                 else "2026-11-18T13:00:00+00:00")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="we4-revocation-required-check-")
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Disposable WE4 Test")
        self.git("config", "user.email", "disposable@example.invalid")
        self.write(check.KEY, self.pub)
        self.write(check.TRUST, json.dumps({
            "schema": check.TRUST_SCHEMA,
            "owner_public_key_sha256": hashlib.sha256(self.pub).hexdigest()
        }))
        self.write(check.STATE, json.dumps(self.state(), sort_keys=True))
        self.base = self.commit()
        self.write(check.STATE, json.dumps(self.state(revision=2, status="REVOKED"),
                                          sort_keys=True))
        self.head = self.commit()

    def tearDown(self):
        self.temp.cleanup()

    def verify(self):
        return check.verify(self.repo, self.base, self.head)

    def test_real_disposable_signature_accepts_only_signed_terminal_state(self):
        result = self.verify()
        self.assertEqual(result["status"], "SIGNED_MONOTONIC_TRANSITION_REQUIRED_CHECK_PASS")
        self.assertEqual(result["new_revision"], 2)
        self.assertFalse(result["production_authority_admitted"])

    def test_change_of_unrelated_file_rejected(self):
        self.write("README.md", "Unauthorized PR payload")
        self.head = self.commit()
        with self.assertRaisesRegex(ValueError, "UNREVIEWED_PR_PATH_CHANGES"):
            self.verify()

    def test_unreviewed_public_key_substitution_rejected(self):
        self.write(check.KEY, b"not-an-owner-public-key\n")
        self.head = self.commit()
        with self.assertRaisesRegex(ValueError, "UNREVIEWED_PR_PATH_CHANGES"):
            self.verify()

    def test_invalid_owner_signature_denied(self):
        state = self.state(revision=2, status="REVOKED")
        state["state"]["revision"] = 3
        self.write(check.STATE, json.dumps(state, sort_keys=True))
        self.head = self.commit()
        with self.assertRaisesRegex(ValueError, "INDEPENDENT_SIGNATURE_REFUSED"):
            self.verify()

    def test_signed_active_to_active_denied(self):
        self.write(check.STATE, json.dumps(self.state(revision=2, status="ACTIVE"),
                                          sort_keys=True))
        self.head = self.commit()
        with self.assertRaisesRegex(ValueError, "REVOCATION_TRANSITION_TERMINAL_ONLY"):
            self.verify()

    def test_duplicate_json_key_denied(self):
        before = self.state(revision=2, status="REVOKED")
        self.write(check.STATE, '{"state":{},' + json.dumps(before)[1:])
        self.head = self.commit()
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
            self.verify()

    def test_symbolic_ref_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "COMMIT_NOT_FULL_SHA"):
            check.verify(self.repo, "HEAD", self.head)

    def test_proposed_symlink_instead_of_regular_state_denied(self):
        target = self.repo / check.STATE
        target.unlink()
        target.symlink_to("../README.md")
        self.head = self.commit()
        with self.assertRaisesRegex(ValueError, "UNREVIEWED_PR_PATH_CHANGES"):
            self.verify()

    def test_same_head_is_not_a_transition(self):
        with self.assertRaisesRegex(ValueError, "NO_STATE_CHANGE"):
            check.verify(self.repo, self.base, self.base)


if __name__ == "__main__":
    unittest.main()

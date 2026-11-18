"""Independent remote branch terminal revocation policy against real test signatures."""
from __future__ import annotations

import hashlib
import unittest

from scripts import public_audience_v2_revocation_transition as transition
from tests.test_public_audience_v2_operator_permit import OwnerPermitSignatureTests


class SignedMonotonicRevocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OwnerPermitSignatureTests.setUpClass()
        cls.owner = OwnerPermitSignatureTests()
        cls.pub = cls.owner.key
        cls.owner_sha = hashlib.sha256(cls.pub).hexdigest()

    @classmethod
    def tearDownClass(cls):
        OwnerPermitSignatureTests.tearDownClass()

    def state(self,*,revision=1,status="ACTIVE",delegation="b"*64,
              time="2026-11-18T12:00:00+00:00"):
        payload={
            "schema":"traffic.public-audience.v2.delegation-revocation-state.v1",
            "delegation_sha256":"a"*64,
            "delegation_id":delegation,
            "status":status,"revision":revision,
            "effective_at_utc":time,
        }
        signed=self.owner.signed(payload)
        return {"state":payload,"signature":signed["signature"]}

    def check(self,old,new):
        return transition.transition(
            old,new,owner_public_key=self.pub,
            trusted_owner_sha256=self.owner_sha)

    def test_real_disposable_owner_signature_accepts_only_irreversible_revocation(self):
        prev=self.state()
        new=self.state(revision=2,status="REVOKED",
                       time="2026-11-18T13:00:00+00:00")
        result=self.check(prev,new)
        self.assertEqual(result["new_revision"],2)
        self.assertFalse(result["branch_ruleset_and_external_trust_physically_admitted"])

    def test_duplicate_or_older_revision_refused(self):
        old=self.state()
        for revision in (0,1,-1):
            with self.subTest(revision=revision),self.assertRaisesRegex(
                ValueError,"REVOCATION_TRANSITION_REVISION_NOT_MONOTONIC"):
                self.check(old,self.state(revision=revision,status="REVOKED",
                        time="2026-11-18T13:00:00+00:00"))

    def test_signed_reactivation_refused_even_with_higher_revision(self):
        revoked=self.state(status="REVOKED",revision=2)
        new_active=self.state(status="ACTIVE",revision=3,
                              time="2026-11-18T13:00:00+00:00")
        with self.assertRaisesRegex(ValueError,"REVOCATION_TRANSITION_TERMINAL_ONLY"):
            self.check(revoked,new_active)

    def test_signed_active_to_active_refused(self):
        with self.assertRaisesRegex(ValueError,"REVOCATION_TRANSITION_TERMINAL_ONLY"):
            self.check(self.state(),self.state(revision=2,status="ACTIVE",
                                time="2026-11-18T13:00:00+00:00"))

    def test_foreign_delegation_refused(self):
        with self.assertRaisesRegex(ValueError,"REVOCATION_TRANSITION_FOREIGN_DELEGATION"):
            self.check(self.state(),self.state(revision=2,status="REVOKED",
                         delegation="c"*64,
                         time="2026-11-18T13:00:00+00:00"))

    def test_forged_owner_signature_refused(self):
        new=self.state(revision=2,status="REVOKED",
                       time="2026-11-18T13:00:00+00:00")
        new["state"]["revision"]=3
        with self.assertRaisesRegex(ValueError,"INDEPENDENT_SIGNATURE_REFUSED"):
            self.check(self.state(),new)

    def test_nonincreasing_clock_refused(self):
        with self.assertRaisesRegex(ValueError,"REVOCATION_TRANSITION_CLOCK_NOT_MONOTONIC"):
            self.check(self.state(),self.state(revision=2,status="REVOKED",
                         time="2026-11-18T11:59:00+00:00"))


if __name__=="__main__":
    unittest.main()

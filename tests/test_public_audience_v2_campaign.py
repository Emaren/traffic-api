from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import public_audience_v2_campaign as campaign


class CampaignTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.source=Path(temp.name)/"source.db"
        self.state=Path(temp.name)/"private.db"
        self.source.write_bytes(b"fixture")

    def test_bounded_cycle_transitions_from_pass_one_to_pass_two(self):
        phase=["PASS1_RUNNING","PASS1_COMPLETE","PASS2_RUNNING","PASS2_COMPLETE"]
        index={"value": -1}
        def step(*args, **kwargs):
            index["value"]+=1
            return {"phase":phase[index["value"]]}
        with (
            patch.object(campaign.pass1,"advance",side_effect=step) as p1,
            patch.object(campaign.pass2,"pass2_step",side_effect=step) as p2,
            patch.object(campaign.pass1,"status",side_effect=lambda _: {
                "phase":phase[index["value"]],
                "raw_scanned":42,"source_max_rowid":99,
            }),
            patch.object(campaign.pass2,"shadow_daily",return_value={
                "2026-10-16":[20,10,5],
            }),
            patch.object(Path,"is_file",return_value=True),
        ):
            result=campaign.cycle(self.source,self.state,
                start="2026-10-16T00:00:00+00:00",
                end="2026-10-20T00:00:00+00:00",
                rows_per_step=5,step_budget=2,
                wall_seconds=20,max_steps=4)
            self.assertEqual(result["phase"],"PASS2_COMPLETE")
            self.assertEqual(result["steps"],4)
            self.assertEqual(p1.call_count,2)
            self.assertEqual(p2.call_count,2)
            self.assertFalse(result["publish_authorized"])
            self.assertFalse(result["semantic_equivalence_certified"])
            self.assertEqual(len(result["shadow_digest_sha256"]),64)

    def test_rejects_invalid_resource_budget_before_work(self):
        with self.assertRaisesRegex(RuntimeError,"bounded cycle"):
            campaign.cycle(self.source,self.state,
                start="",end="",rows_per_step=5,
                step_budget=2,wall_seconds=9999,max_steps=1)

    def test_status_does_not_create_checkpoint_or_publish(self):
        with self.assertRaisesRegex(RuntimeError,"no checkpoint"):
            campaign.audit(self.state)
        self.assertFalse(self.state.exists())


if __name__=="__main__":
    unittest.main()

from __future__ import annotations

import unittest

from scripts import public_audience_v2_parity as parity


class ParityRulesTests(unittest.TestCase):
    def test_equal_historical_rows_except_last_suspect_bucket_are_comparable(self):
        dates=[f"2026-10-{d:02d}" for d in range(1,13)]
        old={day:[100,60,30] for day in dates}
        shadow={day:[100,60,30] for day in dates}
        shadow[dates[-1]]=[1000,600,300]
        shadow["2026-10-13"]=[1110,777,300]
        result=parity.compare_history(shadow,old)
        self.assertEqual(result["status"],"MATCH")
        self.assertEqual(result["compared"],11)
        self.assertTrue(result["shadow_has_legacy_last_day"])
        self.assertEqual(result["new_day_count"],1)

    def test_historical_mismatch_cannot_be_excused_as_trailing_partial_day(self):
        old={f"2026-10-{d:02d}":[100,60,30] for d in range(1,13)}
        shadow=dict(old)
        shadow["2026-10-07"]=[0,0,0]
        result=parity.compare_history(shadow,old)
        self.assertEqual(result["status"],"BLOCKED")
        self.assertEqual(result["mismatch_days"],["2026-10-07"])

    def test_small_legacy_baseline_is_not_authority(self):
        result=parity.compare_history({"2026-10-01":[1,1,1]},{
            "2026-10-01":[1,1,1]})
        self.assertEqual(result["status"],"BLOCKED")
        self.assertEqual(result["compared"],0)

    def test_invalid_shadow_hierarchy_rejected(self):
        old={f"2026-10-{d:02d}":[100,60,30] for d in range(1,13)}
        shadow=dict(old)
        shadow["2026-10-13"]=[3,4,2]
        result=parity.compare_history(shadow,old)
        self.assertEqual(result["status"],"BLOCKED")
        self.assertIn("2026-10-13",result["hierarchy_violations"])


if __name__=="__main__":
    unittest.main()

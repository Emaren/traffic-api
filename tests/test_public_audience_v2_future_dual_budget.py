from __future__ import annotations

import unittest

from scripts import public_audience_v2_future_session_preview as preview


class PreviewModeTimeBudgetTests(unittest.TestCase):
    def test_original_single_pass_clock_unchanged(self):
        self.assertEqual(preview.preview_budget_limit(), 45)
        self.assertEqual(
            preview.preview_budget_limit(
                compare_original=False,
                estimate_boundary_impact=False,
            ), 45,
        )

    def test_reference_historical_stream_remains_bounded_100_seconds(self):
        self.assertEqual(
            preview.preview_budget_limit(compare_original=True), 100,
        )

    def test_midnight_quarantine_dual_pass_gets_full_ab_budget(self):
        # Regression: prior code checked only compare_original and forced
        # quarantine's two complete replays to share the single 40s budget.
        self.assertEqual(
            preview.preview_budget_limit(estimate_boundary_impact=True), 100,
        )

    def test_no_unbounded_escalation_when_both_flags_supplied(self):
        # The CLI independently prohibits combining these two modes.
        # The budget helper must still never exceed the approved 100s cap.
        self.assertEqual(
            preview.preview_budget_limit(
                compare_original=True, estimate_boundary_impact=True,
            ), 100,
        )
        self.assertEqual(preview.MAX_AB_SECONDS, 100)


if __name__ == "__main__":
    unittest.main()

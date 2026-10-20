from __future__ import annotations

import unittest
from datetime import datetime, timezone, timedelta

from scripts.rebuild_public_audience_archive import (
    resolve_archive_end,
    utc_midnight,
)


class PublicAudienceCompleteDayTests(unittest.TestCase):
    def test_default_ends_at_start_of_current_utc_day(self) -> None:
        now = datetime(2026, 10, 20, 6, 15, tzinfo=timezone.utc)
        self.assertEqual(resolve_archive_end(None, now), datetime(2026, 10, 20, tzinfo=timezone.utc))

    def test_local_timezone_never_changes_utc_cutoff(self) -> None:
        now = datetime(2026, 10, 19, 22, 50, tzinfo=timezone(timedelta(hours=-6)))
        self.assertEqual(resolve_archive_end(None, now), datetime(2026, 10, 20, tzinfo=timezone.utc))

    def test_explicit_debug_end_preserved_but_separate_from_published_default(self) -> None:
        now = datetime(2026, 10, 20, 6, 15, tzinfo=timezone.utc)
        self.assertEqual(
            resolve_archive_end("2026-10-19T06:15:00+00:00", now),
            datetime(2026, 10, 19, 6, 15, tzinfo=timezone.utc),
        )

    def test_utc_midnight_is_timezone_aware(self) -> None:
        self.assertEqual(
            utc_midnight(datetime(2026, 10, 19, tzinfo=timezone.utc).date()),
            datetime(2026, 10, 19, tzinfo=timezone.utc),
        )


if __name__ == "__main__":
    unittest.main()

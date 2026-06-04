from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from app.services.traffic.classify import classify_request, detect_route_kind
from app.services.traffic.sessions import build_sessions


WINDOWS_CHROME_UA_1 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)
WINDOWS_CHROME_UA_2 = WINDOWS_CHROME_UA_1.replace("125.0.0.0", "126.0.0.0")
WINDOWS_CHROME_UA_3 = WINDOWS_CHROME_UA_1.replace("125.0.0.0", "127.0.0.0")


class ChainEndpointPollerTests(unittest.TestCase):
    def _entry(
        self,
        *,
        offset_seconds: int,
        path: str,
        ua: str,
        line_offset: int,
    ) -> dict:
        timestamp = datetime(2026, 6, 4, 15, 0, tzinfo=timezone.utc) + timedelta(
            seconds=offset_seconds
        )
        return {
            "ip": "188.40.110.49",
            "timestamp": timestamp,
            "timestamp_iso": timestamp.isoformat(),
            "line_offset": line_offset,
            "raw_path": path,
            "normalized_path": path,
            "referrer_host": "(direct)",
            "ua": ua,
            "host": "aoe2war.com",
            "category": classify_request(ua, path),
            "route_kind": detect_route_kind(path),
        }

    def test_chain_mainnet_routes_are_api_not_pages(self) -> None:
        for path in (
            "/rpc-mainnet/websocket",
            "/rest-mainnet/cosmos/staking/v1beta1/delegations/wolo1abc/rewards",
        ):
            with self.subTest(path=path):
                self.assertEqual(detect_route_kind(path), "api")

    def test_same_ip_chain_polling_is_collapsed_and_not_counted_as_human(self) -> None:
        sessions = build_sessions(
            [
                self._entry(
                    offset_seconds=0,
                    path="/rest-mainnet/cosmos/staking/v1beta1/delegations/wolo1abc/rewards",
                    ua=WINDOWS_CHROME_UA_1,
                    line_offset=1,
                ),
                self._entry(
                    offset_seconds=180,
                    path="/rpc-mainnet/websocket",
                    ua=WINDOWS_CHROME_UA_2,
                    line_offset=2,
                ),
                self._entry(
                    offset_seconds=360,
                    path="/rest-mainnet/cosmos/distribution/v1beta1/delegators/wolo1abc/rewards",
                    ua=WINDOWS_CHROME_UA_3,
                    line_offset=3,
                ),
            ]
        )

        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session["classification_state"], "browser_script")
        self.assertEqual(session["verdict_label"], "Browser Script")
        self.assertTrue(session.get("is_chain_poll_cluster"))
        self.assertEqual(session.get("chain_poll_member_count"), 3)
        self.assertEqual(session["human_confidence"], 0)
        self.assertIn("chain_rpc_poll", session["classification_reasons"])
        self.assertIn("chain infrastructure polling", session["classification_summary"])


if __name__ == "__main__":
    unittest.main()

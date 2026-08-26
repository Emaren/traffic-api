from __future__ import annotations

import inspect
import json
import unittest

from app.services.traffic.browser_events import (
    AUTH_PRESENCE_FRESH_SECONDS,
    _compact_payload,
    _enrich_browser_event_row,
    _propagate_authenticated_identity,
)
from app.services.traffic.overview import (
    _auth_presence_overlaps_session,
    _browser_engagement_key,
    _compact_live_session,
    _is_known_identity_only_signal,
)
from app.services.traffic.parse import (
    parse_json_log_line,
)


def nginx_line(
    *,
    remote_addr: str,
    forwarded_for: str,
) -> str:
    return json.dumps(
        {
            "ts": "2026-08-26T22:55:33+00:00",
            "host": "aoe2war.com",
            "server_name": "aoe2war.com",
            "remote_addr": remote_addr,
            "x_forwarded_for": forwarded_for,
            "method": "POST",
            "request": "POST /api/user/ping HTTP/2.0",
            "request_uri": "/api/user/ping",
            "uri": "/api/user/ping",
            "status": 200,
            "referrer": "https://aoe2war.com/live-games",
            "user_agent": "Mozilla/5.0 Test",
        }
    )


class IdentityTruthV2Tests(
    unittest.TestCase
):
    def test_cloudflare_log_uses_real_forwarded_client_ip(
        self,
    ) -> None:
        row = parse_json_log_line(
            nginx_line(
                remote_addr="172.70.35.185",
                forwarded_for="68.131.37.96",
            )
        )

        self.assertIsNotNone(row)
        self.assertEqual(
            row["ip"],
            "68.131.37.96",
        )

    def test_direct_client_cannot_spoof_forwarded_ip(
        self,
    ) -> None:
        row = parse_json_log_line(
            nginx_line(
                remote_addr="203.0.113.25",
                forwarded_for="68.131.37.96",
            )
        )

        self.assertIsNotNone(row)
        self.assertEqual(
            row["ip"],
            "203.0.113.25",
        )

    def test_fresh_authenticated_identity_propagates_within_session(
        self,
    ) -> None:
        events = [
            {
                "id": 1,
                "received_at": "2026-08-26T22:00:00+00:00",
                "event_type": "auth_presence",
                "session_id": "jim-session",
                "authenticated": True,
                "authenticated_uid": "jim-uid",
                "known_visitor_label": "Jim",
                "known_visitor_kind": "known_player",
            },
            {
                "id": 2,
                "received_at": "2026-08-26T22:02:00+00:00",
                "event_type": "click",
                "session_id": "jim-session",
                "authenticated": False,
            },
        ]

        result = _propagate_authenticated_identity(
            events
        )

        self.assertTrue(
            result[1]["authenticated"]
        )
        self.assertTrue(
            result[1][
                "authentication_fresh"
            ]
        )
        self.assertEqual(
            result[1][
                "authenticated_uid"
            ],
            "jim-uid",
        )

    def test_stale_authenticated_identity_does_not_survive_long_session(
        self,
    ) -> None:
        events = [
            {
                "id": 1,
                "received_at": "2026-08-26T06:37:23+00:00",
                "event_type": "auth_presence",
                "session_id": "jim-session",
                "authenticated": True,
                "authenticated_uid": "jim-uid",
                "known_visitor_label": "Jim",
                "known_visitor_kind": "known_player",
            },
            {
                "id": 2,
                "received_at": "2026-08-26T22:47:50+00:00",
                "event_type": "visibility_change",
                "session_id": "jim-session",
                "authenticated": False,
            },
        ]

        result = _propagate_authenticated_identity(
            events
        )

        self.assertFalse(
            result[1]["authenticated"]
        )
        self.assertFalse(
            result[1][
                "authentication_fresh"
            ]
        )
        self.assertEqual(
            result[1][
                "previously_authenticated_uid"
            ],
            "jim-uid",
        )
        self.assertEqual(
            result[1][
                "known_visitor_detail"
            ],
            "previously authenticated AoE2WAR session",
        )

    def test_auth_freshness_window_is_bounded(
        self,
    ) -> None:
        self.assertEqual(
            AUTH_PRESENCE_FRESH_SECONDS,
            180,
        )

    def test_browser_engagement_key_separates_user_agents(
        self,
    ) -> None:
        jim = _browser_engagement_key(
            "aoe2hdbets",
            "68.131.37.96",
            "Edge/151",
        )

        other = _browser_engagement_key(
            "aoe2hdbets",
            "68.131.37.96",
            "Chrome/151",
        )

        self.assertNotEqual(
            jim,
            other,
        )

    def test_auth_presence_must_overlap_server_session(
        self,
    ) -> None:
        session = {
            "started_at": "2026-08-26T22:45:00+00:00",
            "ended_at": "2026-08-26T22:55:40+00:00",
        }

        self.assertTrue(
            _auth_presence_overlaps_session(
                session,
                "2026-08-26T22:46:34+00:00",
            )
        )

        self.assertFalse(
            _auth_presence_overlaps_session(
                session,
                "2026-08-25T06:37:23+00:00",
            )
        )


    def test_public_browser_payload_cannot_self_assert_authentication(
        self,
    ) -> None:
        payload = json.loads(
            _compact_payload(
                {
                    "auth_verified": True,
                    "authenticated_uid": "fake-uid",
                    "authenticated_label": "Fake Jim",
                    "authenticated_kind": "known_player",
                    "source": "browser",
                }
            )
        )

        self.assertNotIn(
            "auth_verified",
            payload,
        )
        self.assertNotIn(
            "authenticated_uid",
            payload,
        )

    def test_trusted_auth_payload_preserves_server_verified_identity(
        self,
    ) -> None:
        payload = json.loads(
            _compact_payload(
                {
                    "auth_verified": True,
                    "authenticated_uid": "jim-uid",
                    "authenticated_label": "Jim",
                    "authenticated_kind": "known_player",
                },
                trusted_auth=True,
            )
        )

        self.assertTrue(
            payload["auth_verified"]
        )
        self.assertEqual(
            payload[
                "authenticated_uid"
            ],
            "jim-uid",
        )

    def test_non_auth_event_with_forged_payload_is_not_authenticated(
        self,
    ) -> None:
        event = _enrich_browser_event_row(
            {
                "id": 999,
                "received_at": "2026-08-26T22:55:33+00:00",
                "occurred_at": "2026-08-26T22:55:33+00:00",
                "event_type": "click",
                "session_id": "forged-session",
                "visitor_id": "forged-visitor",
                "ip": "203.0.113.77",
                "path": "/",
                "user_agent": "Mozilla/5.0 Test",
                "country": "United States",
                "payload_json": json.dumps(
                    {
                        "auth_verified": True,
                        "authenticated_uid": "jim-uid",
                        "authenticated_label": "Jim",
                    }
                ),
            }
        )

        self.assertFalse(
            event["authenticated"]
        )
        self.assertEqual(
            event[
                "authenticated_uid"
            ],
            "",
        )



    def test_fresh_authenticated_player_is_not_identity_only(
        self,
    ) -> None:
        session = {
            "authenticated": True,
            "known_visitor_confirmed": True,
            "known_identity_signal": False,
            "classification_state": "likely_human",
            "human_confirmed": False,
        }

        self.assertFalse(
            _is_known_identity_only_signal(
                session
            )
        )

    def test_static_known_identity_without_auth_stays_identity_only(
        self,
    ) -> None:
        session = {
            "authenticated": False,
            "known_visitor_confirmed": True,
            "known_identity_signal": True,
            "classification_state": "likely_human",
            "human_confirmed": False,
        }

        self.assertTrue(
            _is_known_identity_only_signal(
                session
            )
        )



    def test_live_serializer_preserves_authenticated_truth(
        self,
    ) -> None:
        source = inspect.getsource(
            _compact_live_session
        )

        self.assertIn(
            'compact["authenticated"]',
            source,
        )
        self.assertIn(
            'compact["authenticated_uid"]',
            source,
        )



if __name__ == "__main__":
    unittest.main()

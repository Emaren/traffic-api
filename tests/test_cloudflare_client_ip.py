"""Trusted Cloudflare IP provenance; never trust user-supplied proxy headers."""

import unittest

from app.services.traffic.parse import client_ip_from_json_payload, parse_json_log_line


class CloudflareProvenanceTests(unittest.TestCase):
    def test_trusted_cf_peer_prefers_single_client_header(self):
        self.assertEqual(
            client_ip_from_json_payload({
                "remote_addr": "172.68.23.16",
                "x_forwarded_for": "203.0.113.77, 198.51.100.2",
                "cf_connecting_ip": "198.51.100.18",
            }),
            "198.51.100.18",
        )

    def test_untrusted_socket_cannot_spoof_cf_header_or_xff(self):
        self.assertEqual(
            client_ip_from_json_payload({
                "remote_addr": "65.108.127.124",
                "cf_connecting_ip": "198.51.100.18",
                "x_forwarded_for": "203.0.113.77",
            }),
            "65.108.127.124",
        )

    def test_legacy_cf_json_keeps_trusted_xff_fallback(self):
        self.assertEqual(
            client_ip_from_json_payload({
                "remote_addr": "104.22.160.61",
                "x_forwarded_for": "2001:56a:fba3:5900:70ca:e24b:90c:3c82",
            }),
            "2001:56a:fba3:5900:70ca:e24b:90c:3c82",
        )

    def test_invalid_header_falls_back_safely(self):
        self.assertEqual(
            client_ip_from_json_payload({
                "remote_addr": "172.68.23.16",
                "cf_connecting_ip": "not-an-ip",
                "x_forwarded_for": "198.51.100.4, 172.68.23.16",
            }),
            "198.51.100.4",
        )
        self.assertEqual(
            client_ip_from_json_payload({
                "remote_addr": "172.68.23.16",
                "cf_connecting_ip": "not-an-ip",
                "x_forwarded_for": "spoofed",
            }),
            "172.68.23.16",
        )


if __name__ == "__main__":
    unittest.main()

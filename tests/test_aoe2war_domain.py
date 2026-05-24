from __future__ import annotations

import unittest

from app.services.traffic.normalize import is_allowed_host, normalize_host, project_for_host
from app.services.traffic.overview import _hosts_for_projects


class AoE2WarDomainTests(unittest.TestCase):
    def test_new_and_legacy_hosts_resolve_to_same_project(self) -> None:
        for host in (
            "aoe2war.com",
            "www.aoe2war.com",
            "api-prodn.aoe2war.com",
            "aoe2hdbets.com",
            "www.aoe2hdbets.com",
            "api-prodn.aoe2hdbets.com",
        ):
            with self.subTest(host=host):
                self.assertTrue(is_allowed_host(host))
                self.assertEqual(project_for_host(host)["slug"], "aoe2hdbets")

    def test_aoe2war_is_canonical_reporting_host(self) -> None:
        self.assertEqual(normalize_host("https://www.aoe2hdbets.com:443/lobby"), "aoe2war.com")
        self.assertEqual(normalize_host("https://www.aoe2war.com:443/lobby"), "aoe2war.com")
        self.assertEqual(normalize_host("api-prodn.aoe2hdbets.com"), "api-prodn.aoe2war.com")

    def test_project_queries_include_legacy_and_new_stored_hosts(self) -> None:
        hosts = set(_hosts_for_projects({"aoe2hdbets"}) or [])

        self.assertIn("aoe2war.com", hosts)
        self.assertIn("api-prodn.aoe2war.com", hosts)
        self.assertIn("aoe2hdbets.com", hosts)
        self.assertIn("api-prodn.aoe2hdbets.com", hosts)


if __name__ == "__main__":
    unittest.main()

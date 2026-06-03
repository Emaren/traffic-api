from __future__ import annotations

import unittest

from app.services.traffic.normalize import is_allowed_host, normalize_host, project_for_host
from app.services.traffic.overview import _hosts_for_projects


class NewDomainMappingTests(unittest.TestCase):
    def test_new_app_and_chain_hosts_are_allowed(self) -> None:
        expected = {
            "usetab.ca": "usetab",
            "www.usetab.ca": "usetab",
            "chain.usetab.ca": "creditchain",
            "ascendai.one": "ascendai",
            "www.ascendai.one": "ascendai",
            "chain.ascendai.one": "ascendchain",
            "chains.ascendai.one": "ascend-chains",
        }

        for host, slug in expected.items():
            with self.subTest(host=host):
                self.assertTrue(is_allowed_host(host))
                self.assertEqual(project_for_host(host)["slug"], slug)

    def test_public_app_www_hosts_normalize_to_canonical_hosts(self) -> None:
        self.assertEqual(normalize_host("https://www.usetab.ca:443/protocol"), "usetab.ca")
        self.assertEqual(normalize_host("https://www.ascendai.one:443/"), "ascendai.one")

    def test_project_queries_include_new_hosts(self) -> None:
        self.assertEqual(_hosts_for_projects({"usetab"}), ["usetab.ca", "www.usetab.ca"])
        self.assertEqual(_hosts_for_projects({"creditchain"}), ["chain.usetab.ca"])
        self.assertEqual(_hosts_for_projects({"ascendai"}), ["ascendai.one", "www.ascendai.one"])
        self.assertEqual(_hosts_for_projects({"ascendchain"}), ["chain.ascendai.one"])
        self.assertEqual(_hosts_for_projects({"ascend-chains"}), ["chains.ascendai.one"])


if __name__ == "__main__":
    unittest.main()

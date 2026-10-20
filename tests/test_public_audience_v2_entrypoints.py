"""Prevent accidental non-functional V2 production commands (missing app import)."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    "public_audience_v2_checkpoint",
    "public_audience_v2_sessions",
    "public_audience_v2_campaign",
    "public_audience_v2_preflight",
    "public_audience_v2_parity",
)


class V2CliInvocationTests(unittest.TestCase):
    def test_both_direct_script_and_module_help_are_importable_without_pythonpath(self):
        # --help is deliberately non-mutating; DO NOT run 'cycle' or 'advance'
        # against a real Traffic source from CI or this smoke regression.
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        for script in SCRIPTS:
            with self.subTest(script=script):
                for command in (
                    [sys.executable, str(ROOT / "scripts" / (script + ".py")), "--help"],
                    [sys.executable, "-m", "scripts." + script, "--help"],
                ):
                    output = subprocess.run(
                        command, cwd=ROOT, env=env, text=True,
                        capture_output=True, timeout=20, check=False,
                    )
                    self.assertEqual(
                        output.returncode, 0,
                        f"{' '.join(command)} exited {output.returncode}: "
                        f"{output.stderr[:1200]}",
                    )
                    self.assertIn("usage:", output.stdout.lower())


if __name__ == "__main__":
    unittest.main()

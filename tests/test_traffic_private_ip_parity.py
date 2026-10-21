import unittest
from scripts import public_audience_v2_forward_ip_parity as parity


class ParityGuardTests(unittest.TestCase):
    def test_refuses_unbounded_input(self):
        with self.assertRaises(RuntimeError):
            parity.require(False, 'invalid')

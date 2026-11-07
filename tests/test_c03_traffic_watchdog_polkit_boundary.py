"""C03 source-only tests for unprivileged Traffic watchdog plus narrow Polkit."""
from __future__ import annotations
import configparser, io, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
UNIT=ROOT/'ops/systemd/traffic-watchdog.service'
SCRIPT=ROOT/'ops/traffic-watchdog-unprivileged.sh'
RULE=ROOT/'ops/polkit/49-aoe2war-traffic-watchdog-restart.rules'
EXPECT={
 'Type':'oneshot','User':'traffic-watchdog','Group':'traffic-watchdog',
 'WorkingDirectory':'/','Environment':'PATH=/usr/bin:/bin',
 'ExecStart':'/usr/local/libexec/aoe2war-traffic-watchdog-20261107.sh',
 'NoNewPrivileges':'yes','CapabilityBoundingSet':'','AmbientCapabilities':'',
 'PrivateTmp':'yes','ProtectHome':'yes','ProtectSystem':'strict',
 'ProtectKernelTunables':'yes','ProtectKernelModules':'yes',
 'ProtectControlGroups':'yes','RestrictNamespaces':'yes',
 'RestrictSUIDSGID':'yes','LockPersonality':'yes','PrivateDevices':'yes',
 'RestrictAddressFamilies':'AF_UNIX AF_INET AF_INET6',
 'InaccessiblePaths':'-/run/postgresql -/var/run/postgresql',
 'UMask':'0077','TimeoutStartSec':'90'
}
def qualify(raw):
 c=configparser.ConfigParser(interpolation=None,strict=True)
 c.read_file(io.StringIO(raw))
 assert set(c.sections())=={'Unit','Service'}
 s=c['Service']
 for k,v in EXPECT.items():
  assert s.get(k,None)==v,'DRIFT_'+k
 assert raw.count('ExecStart=')==1
 for k in ('ExecStartPre','ExecStartPost','BindPaths','BindReadOnlyPaths',
           'SupplementaryGroups','RootDirectory','RootImage','EnvironmentFile'):
  assert k not in s
 return True

class C03TrafficWatchdogTests(unittest.TestCase):
 def test_unit(self):
  self.assertTrue(qualify(UNIT.read_text()))
 def test_adversarial(self):
  raw=UNIT.read_text()
  for a,b in [
   ('User=traffic-watchdog','User=root'),
   ('NoNewPrivileges=yes','NoNewPrivileges=no'),
   ('CapabilityBoundingSet=\n','CapabilityBoundingSet=CAP_NET_ADMIN\n'),
   ('AmbientCapabilities=\n','AmbientCapabilities=CAP_NET_RAW\n'),
   ('ProtectSystem=strict','ProtectSystem=full'),
   ('ProtectHome=yes','ProtectHome=no'),
   ('RestrictNamespaces=yes','RestrictNamespaces=no'),
   ('RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6','RestrictAddressFamilies=~'),
   ('InaccessiblePaths=-/run/postgresql -/var/run/postgresql','InaccessiblePaths='),
   ('ExecStart=/usr/local/libexec/aoe2war-traffic-watchdog-20261107.sh','ExecStart=/bin/bash'),
  ]:
   with self.subTest(a=a):
    self.assertIn(a,raw)
    with self.assertRaises((AssertionError,configparser.Error)):
     qualify(raw.replace(a,b,1))
 def test_polkit_exact(self):
  raw=RULE.read_text()
  self.assertEqual(raw.count('polkit.addRule'),1)
  self.assertIn('subject.user !== "traffic-watchdog"',raw)
  self.assertIn('action.id !== "org.freedesktop.systemd1.manage-units"',raw)
  self.assertIn('verb === "restart"',raw)
  self.assertIn('unit === "traffic-api.service"',raw)
  self.assertIn('unit === "traffic-web.service"',raw)
  self.assertEqual(raw.count('polkit.Result.YES'),1)
  self.assertEqual(raw.count('return;'),2)
  self.assertNotIn('manage-unit-files',raw)
 def test_script_bounded_restart(self):
  s=SCRIPT.read_text()
  self.assertEqual(s.count('systemctl restart traffic-web.service'),2)
  self.assertEqual(s.count('systemctl restart traffic-api.service'),1)
  self.assertNotIn('sudo ',s)
  self.assertNotIn('wolochaind',s)
  self.assertTrue(s.startswith('#!/usr/bin/env bash'))
 def test_duplicate_key_denied(self):
  with self.assertRaises(configparser.Error):
   qualify(UNIT.read_text()+'\nNoNewPrivileges=no\n')
if __name__=='__main__':unittest.main()

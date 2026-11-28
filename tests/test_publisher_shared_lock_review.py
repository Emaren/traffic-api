"""Synthetic lock tests; no production access."""
import os,tempfile,unittest
from pathlib import Path
from scripts import public_audience_v2_runner as runner
class SharedLockReview(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
  self.p=Path(self.t.name).resolve()/'lock'
  self.p.touch(); self.p.chmod(0o640)
  self.fd=os.open(self.p,os.O_RDONLY); self.addCleanup(os.close,self.fd)
 def verify(self):
  runner.verify_worker_lock(self.fd,self.p,uid=os.getuid(),gid=os.getgid(),mode=0o640)
 def test_expected_inode(self):
  self.verify()
 def test_replaced_inode(self):
  self.p.rename(self.p.with_suffix('.old'));self.p.touch();self.p.chmod(0o640)
  with self.assertRaisesRegex(ValueError,'SHARED_PROJECT_LOCK_NOT_ADMITTED'):self.verify()
 def test_wrong_mode(self):
  self.p.chmod(0o666)
  with self.assertRaisesRegex(ValueError,'SHARED_PROJECT_LOCK_NOT_ADMITTED'):self.verify()
 def test_hardlink(self):
  os.link(self.p,self.p.with_suffix('.alias'))
  with self.assertRaisesRegex(ValueError,'SHARED_PROJECT_LOCK_NOT_ADMITTED'):self.verify()
 def test_production_private_lock_rejected(self):
  cfg={'worker_lock':str(self.p),'checkpoint_dir':str(self.p.parent)}
  with self.assertRaisesRegex(ValueError,'SHARED_PROJECT_LOCK_PATH'):runner.worker_lock_policy(cfg,trust_uid=0)

 def test_service_owned_parent_rejected(self):
  from unittest.mock import patch
  cfg={'worker_lock':str(self.p),'checkpoint_dir':str(self.p.parent),'run_uid':os.getuid(),'run_gid':os.getgid()}
  self.p.parent.chmod(0o755)
  if os.getuid()==0:self.skipTest('nonroot fixture required')
  with patch.object(runner,'PRODUCTION_ROLLUP_LOCK',self.p):
   with self.assertRaisesRegex(ValueError,'SHARED_PROJECT_LOCK_DIRECTORY'):runner.worker_lock_policy(cfg,trust_uid=0)

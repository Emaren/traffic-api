import hashlib,sqlite3,unittest
from datetime import datetime,timezone
from scripts import public_audience_v3_registry_continuity as w
class RegistryWitness(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');self.addCleanup(self.db.close)
        for t in w.TABLES:self.db.execute(f'CREATE TABLE {t}(id INTEGER PRIMARY KEY, label TEXT)')
        self.db.execute('CREATE TABLE traffic_entries(id INTEGER PRIMARY KEY)');self.db.commit()
        self.pins={k:hashlib.sha256(v.encode()).hexdigest() for k,v in w.schema_objects(self.db).items()}
        self.db.execute('BEGIN IMMEDIATE');self.start=w.install_in_transaction(self.db,self.pins);self.db.commit()
    def snap(self):
        self.db.execute('BEGIN');s=w.snapshot(self.db);self.db.commit();return s
    def check(self,s):
        return w.compare(self.start,s,day='2026-11-29',baseline_utc=datetime(2026,11,28,23,29,tzinfo=timezone.utc),cutoff_utc=datetime(2026,11,30,tzinfo=timezone.utc),now=datetime(2026,11,30,0,31,tzinfo=timezone.utc))
    def test_ingestion_does_not_change_witness(self):
        self.db.execute('INSERT INTO traffic_entries VALUES(1)');self.db.commit()
        self.assertFalse(self.check(self.snap())['publication_authorized'])
    def test_insert_delete_return_to_same_registry_detected(self):
        for t in w.TABLES:
            self.db.execute(f'INSERT INTO {t} VALUES(1,\'fixture\')');self.db.execute(f'DELETE FROM {t} WHERE id=1')
        self.db.commit();s=self.snap();self.assertEqual(s['mutation_count'],4);self.assertEqual(s['registries'],self.start['registries'])
        with self.assertRaises(ValueError):self.check(s)
    def test_update_and_replace_detected(self):
        t=w.TABLES[0];self.db.execute(f'INSERT INTO {t} VALUES(1,\'x\')');self.db.execute(f'UPDATE {t} SET label=\'y\'');self.db.execute(f'INSERT OR REPLACE INTO {t} VALUES(1,\'x\')');self.db.commit();self.assertGreaterEqual(self.snap()['mutation_count'],3)
    def test_rolled_back_mutation_not_counted(self):
        self.db.execute(f'INSERT INTO {w.TABLES[0]} VALUES(1,\'x\')');self.db.rollback();self.assertEqual(self.start,self.snap())
    def test_ledger_update_delete_denied(self):
        self.db.execute(f'INSERT INTO {w.TABLES[0]} VALUES(1,\'x\')');self.db.commit()
        for op in (f'UPDATE {w.LEDGER} SET operation=\'DELETE\'',f'DELETE FROM {w.LEDGER}'):
            with self.assertRaises(sqlite3.IntegrityError):self.db.execute(op)
        self.db.rollback()
    def test_schema_recreate_detected(self):
        name,sql=next(iter(w.TRIGGERS.items()));self.db.execute(f'DROP TRIGGER {name}');self.db.execute(sql);self.db.commit()
        with self.assertRaises(ValueError):self.check(self.snap())
    def test_missing_trigger_denied(self):
        self.db.execute(f'DROP TRIGGER {next(iter(w.TRIGGERS))}');self.db.commit()
        with self.assertRaises(ValueError):self.snap()
    def test_repeat_install_denied(self):
        self.db.execute('BEGIN IMMEDIATE')
        with self.assertRaises(ValueError):w.install_in_transaction(self.db,self.pins)
        self.db.rollback()

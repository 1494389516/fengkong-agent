import json,os,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
class MigrationArchive(unittest.TestCase):
    def test_legacy_requires_explicit_migration(self):
        from agent.investigations import _db
        from agent.migrate_investigations import migrate
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'FK_DATA_DIR':root}):
            source=sqlite3.connect(str(Path(root)/'online.sqlite3'))
            source.execute('CREATE TABLE cases(case_id TEXT PRIMARY KEY,tenant TEXT,app TEXT,entity TEXT,bucket INTEGER,body TEXT)')
            source.execute("INSERT INTO cases VALUES('c','t','a','u',1,'{}')");source.commit();source.close()
            with self.assertRaisesRegex(RuntimeError,'migration|migrate'):_db()
            self.assertEqual(migrate()['cases'],1)
            db=_db();self.assertEqual(db.execute('SELECT case_id FROM cases').fetchone()[0],'c');db.close()
            self.assertEqual(migrate()['cases'],1)
    def test_knowledge_archive_is_content_verified(self):
        from agent.rag.store import ingest,archived_index
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'FK_DATA_DIR':root}):
            meta=ingest('knowledge');old=archived_index(meta['index_digest'])
            self.assertTrue(old[1])
            path=Path(root)/'knowledge_archive'/(meta['index_digest']+'.json')
            obj=json.loads(path.read_text());obj['chunks'][0]['text']='poisoned';path.write_text(json.dumps(obj))
            with self.assertRaises(ValueError):archived_index(meta['index_digest'])
if __name__=='__main__':unittest.main()

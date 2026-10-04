import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class Revisions(unittest.TestCase):
    def test_new_evidence_is_new_immutable_revision(self):
        from agent.tools.online_store import connect
        from agent.investigations import consume_decision_outbox, _db
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'FK_DATA_DIR':root}):
            def add(n):
                db=connect()
                event={'uid':'target', 'event_id':'e'+str(n), 'ts':100+n, 'device_id':'d'}
                record={'action':'review','event':event,'evaluated_at':200+n,'tenant_id':'t','app_id':'a', 'decision_id':'d'+str(n)}
                db.execute('INSERT INTO outbox(decision_id,body) VALUES(?,?)', ('d'+str(n),json.dumps(record)))
                db.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',('t','a','e'+str(n),100+n,100+n,json.dumps(event)))
                db.commit();db.close()
            add(1);consume_decision_outbox()
            db=_db();first=db.execute('SELECT snapshot FROM investigation_tasks').fetchone()[0];db.close()
            add(2);consume_decision_outbox();self.assertEqual(consume_decision_outbox(),0)
            db=_db();rows=db.execute('SELECT snapshot FROM investigation_tasks ORDER BY rowid').fetchall()
            self.assertEqual(len(rows),2)
            self.assertEqual(rows[0][0],first)
            self.assertEqual(json.loads(rows[1][0])['revision'],2)
            self.assertEqual(json.loads(rows[1][0])['decision_ids'],['d1','d2'])
            db.close()

if __name__=='__main__':unittest.main()

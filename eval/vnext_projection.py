import ast
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class ProjectionContracts(unittest.TestCase):
    def test_http_does_not_project(self):
        import serve
        tree = ast.parse(inspect.getsource(serve))
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                             and n.func.id == 'consume_decision_outbox' for n in ast.walk(tree)))

    def test_http_response_survives_failed_projector(self):
        import hashlib, http.client, threading, time
        from http.server import ThreadingHTTPServer
        import serve
        with tempfile.TemporaryDirectory() as root:
            auth=Path(root)/'auth.json'
            auth.write_text(json.dumps({hashlib.sha256(b'http-test').hexdigest():dict(
                principal='business',tenant='t',app='a',data_dir=root,source_kind='business',
                permissions=['decisions.write'],expires_at=time.time()+60)}))
            with patch.dict(os.environ,{'FK_AUTH_CONFIG':str(auth)}), patch('serve._validate_event',return_value=None), \
                 patch('serve._decide',return_value={'action':'review'}), \
                 patch('agent.investigations.consume_decision_outbox',side_effect=RuntimeError('blocked projector')) as projector:
                server=ThreadingHTTPServer(('127.0.0.1',0),serve.Handler)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    client=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
                    client.request('POST','/decide','{}',{'Authorization':'Bearer http-test','Content-Type':'application/json'})
                    response=client.getresponse();body=json.loads(response.read());client.close()
                    self.assertEqual(response.status,200)
                    self.assertEqual(body['investigation_projection_status'],'pending')
                    projector.assert_not_called()
                finally:server.shutdown();server.server_close();thread.join()

    def test_replay_separate_store(self):
        from agent.tools.online_store import connect
        from agent.investigations import consume_decision_outbox, _db
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with patch.dict(os.environ, {'FK_DATA_DIR': str(root/'evidence'),
                                         'FK_AGENT_STATE_ROOT': str(root/'state')}):
                db = connect()
                record = {'action': 'pass', 'tenant_id': 'a', 'app_id': 'app'}
                db.execute('INSERT INTO outbox(decision_id,body) VALUES(?,?)', ('d1',json.dumps(record)))
                db.commit(); db.close()
                self.assertEqual(consume_decision_outbox(), 1)
                self.assertEqual(consume_decision_outbox(), 0)
                db = _db()
                self.assertEqual(db.execute('SELECT count(*) FROM investigation_seen').fetchone()[0], 1)
                db.close()
                db = connect()
                self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='cases'").fetchone())
                self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0],1)
                db.close()

if __name__ == '__main__': unittest.main()

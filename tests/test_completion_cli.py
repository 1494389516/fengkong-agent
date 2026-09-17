import hashlib,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
class CliScopeTests(unittest.TestCase):
 def test_local_scope_explicit_no_empty_privilege(self):
  import main
  with patch.dict(os.environ,{'FK_ENV':'development'},clear=True):
   with main.cli_scope('tenant-a','data',['read']):
    from agent.tools.capability import get_scope
    scope=get_scope();from agent.tools.datasource import data_dir
    self.assertEqual(data_dir(),Path('data').resolve());self.assertTrue(scope.principal.startswith('os:'));self.assertTrue(scope.permits('read'));self.assertFalse(scope.permits('propose'))
   self.assertIsNone(get_scope())
 def test_production_credential_binding_cannot_expand(self):
  import main
  with tempfile.TemporaryDirectory() as td:
   registry={hashlib.sha256(b'token').hexdigest():{'principal':'alice','tenant':'a','app':'app','data_dir':td,'source_kind':'operator','permissions':['agent.run'],'capabilities':['read'],'expires_at':time.time()+60}}
   path=Path(td)/'auth';path.write_text(json.dumps(registry))
   with patch.dict(os.environ,{'FK_ENV':'production','FK_AUTH_CONFIG':str(path),'FK_AGENT_TOKEN':'token'}):
    with main.cli_scope('forged','/tmp/forged',['read','execute']):
     from agent.tools.capability import get_scope
     from agent.tools.datasource import data_dir
     scope=get_scope();self.assertEqual(scope.principal,'alice');self.assertEqual(scope.tenant,'a');self.assertEqual(data_dir(),Path(td));self.assertFalse(scope.permits('execute'))
    with patch.dict(os.environ,{'FK_AGENT_TOKEN':'bad'}):
     with self.assertRaises(PermissionError):
      with main.cli_scope('a',td,['read']):pass

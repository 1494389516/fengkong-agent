import json,unittest
from pathlib import Path
import yaml
class DeploymentIsolation(unittest.TestCase):
 def test_collector_only_secret_mounts_and_operations(self):
  root=Path(__file__).resolve().parents[1]/'deploy'
  services=yaml.safe_load((root/'compose.yaml').read_text())['services']
  collector=services['collector'];self.assertIn('FK_COLLECTOR_KEYS',collector['environment'])
  for name in ('agent','runtime','controller','publisher'):
   mounts=' '.join(services[name]['volumes'])
   for secret in ('collector-keys.json','identity.key','apple-app-attest-root.pem'):
    self.assertNotIn(secret,mounts)
  sdk=json.loads((root/'collector-registry.example.json').read_text())
  runtime=json.loads((root/'runtime-registry.example.json').read_text())
  self.assertTrue(all(v['permissions']==['reports.write'] for v in sdk.values()))
  self.assertTrue(all('reports.write' not in v['permissions'] for v in runtime.values()))
  self.assertTrue(all('decisions.write' not in v['permissions'] for v in sdk.values()))

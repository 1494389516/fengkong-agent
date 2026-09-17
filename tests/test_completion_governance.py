import hashlib,json,subprocess,sys,tempfile,unittest,time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from agent.control_plane import ReleaseController
class CompletionGovernance(unittest.TestCase):
 def test_real_process_signed_publish_tamper_and_rollback(self):
  from agent.release_publisher import SignedBundleReader
  with tempfile.TemporaryDirectory() as td:
   root=Path(td); key=Ed25519PrivateKey.generate()
   (root/'key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
   (root/'pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
   creds={hashlib.sha256(t.encode()).hexdigest():{'principal':t,'roles':[r]} for t,r in [('p','proposer'),('v','validator'),('s','shadow_runner'),('a','reviewer'),('r','release_controller')]}
   c=ReleaseController(root/'journal',creds)
   b={'rules':{'R001':1},'model':'m','features':'f','sdk_contract':'s','challenge':'c','fallback':'review','code_digest':'c','data_digest':'d','canary_max_false_positive_delta':.01}
   b.update({k:{} for k in ('policy','strategy','feature','list','graph','versions')})
   b['model']={}
   b['list']={'records':[]}
   rec=c.propose('p',b)
   proof={'bundle_digest':rec['digest'],'passed':True}
   for t,stage in [('v','Validated'),('s','Shadow'),('a','Approved'),('r','Canary'),('r','Active')]: c.transition(t,rec['id'],stage,{**proof,'false_positive_delta':0})
   cmd=[sys.executable,'-m','agent.release_publisher','--store',str(root/'journal'),'--output',str(root/'out'),'--private-key',str(root/'key')]
   subprocess.run(cmd,check=True,capture_output=True)
   reader=SignedBundleReader(root/'out',root/'pub'); first=reader.read(); self.assertEqual(first['bundle'],b)
   c.rollback('r',rec['id'],'incident'); subprocess.run(cmd,check=True,capture_output=True)
   second=reader.read();self.assertNotEqual(first['activation']['id'],second['activation']['id'])
   path=root/'out'/'bundles'/(second['activation']['id']+'.json');doc=json.loads(path.read_text());doc['payload']['bundle']['fallback']='allow';path.write_text(json.dumps(doc))
   with self.assertRaises(ValueError): reader.read()
 def test_strict_auth_scope_expiry_and_evidence(self):
  with tempfile.TemporaryDirectory() as td:
   creds={hashlib.sha256(b'p').hexdigest():{'principal':'alice','roles':['proposer'],'scopes':['tenant:a'],'expires_at':time.time()-1}}
   c=ReleaseController(Path(td)/'journal',creds,strict=True,scope='tenant:a')
   with self.assertRaises(PermissionError):c.propose('p',{})
   creds[hashlib.sha256(b'p').hexdigest()]['expires_at']=time.time()+60
   c=ReleaseController(Path(td)/'journal',creds,strict=True,scope='tenant:b')
   with self.assertRaises(PermissionError):c.propose('p',{})
 def test_strict_evidence_cannot_be_substituted_or_self_approved(self):
  from agent.control_plane import digest
  with tempfile.TemporaryDirectory() as td:
   creds={hashlib.sha256(t.encode()).hexdigest():{'principal':t,'roles':[r],'scopes':['tenant:a'],'expires_at':time.time()+600} for t,r in [('p','proposer'),('v','validator'),('s','shadow_runner'),('a','reviewer'),('r','release_controller')]}
   c=ReleaseController(Path(td)/'journal',creds,strict=True,scope='tenant:a')
   b={'rules':{'R001':1},'model':{},'features':'f','sdk_contract':'s','challenge':'c','fallback':'review','code_digest':'c','data_digest':'d','canary_max_false_positive_delta':.01,**{k:{} for k in ('policy','strategy','feature','list','graph','versions')}}
   rec=c.propose('p',b);e={'scope':'tenant:a','expires_at':time.time()+60,'sample_count':50}
   proof={'bundle_digest':rec['digest'],'passed':True,'baseline_activation':None,'evidence':e,'evidence_digest':digest(e)}
   with self.assertRaises(ValueError):c.transition('v',rec['id'],'Validated',{**proof,'evidence':{**e,'sample_count':51}})
   with self.assertRaises(ValueError):c.transition('v',rec['id'],'Validated',{**proof,'baseline_activation':'stale'})
   c.transition('v',rec['id'],'Validated',proof)
   c.transition('s',rec['id'],'Shadow',proof)
   c.credentials[hashlib.sha256(b'p').hexdigest()]['roles'].append('reviewer')
   with self.assertRaises(PermissionError):c.transition('p',rec['id'],'Approved',proof)
   c.transition('a',rec['id'],'Approved',proof)
   c.transition('r',rec['id'],'Canary',proof)
   c.transition('r',rec['id'],'Active',{**proof,'false_positive_delta':0})
   self.assertIsNotNone(c.snapshot()['active'])

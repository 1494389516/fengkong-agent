"""Software-generated protocol fixtures, NOT Apple hardware attestation evidence."""
import hashlib, unittest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from agent.app_attest import verify_assertion, AssertionError as AppAssertionError

def cbor(value):
    def head(major,n):
        if n<24:return bytes([major+n])
        if n<256:return bytes([major+24,n])
        return bytes([major+25])+n.to_bytes(2,'big')
    if isinstance(value,int):return head(0 if value>=0 else 0x20,value if value>=0 else -1-value)
    if isinstance(value,dict):return head(0xa0,len(value))+b''.join(cbor(k)+cbor(v) for k,v in value.items())
    if isinstance(value,list):return head(0x80,len(value))+b''.join(cbor(v) for v in value)
    raw=value.encode() if isinstance(value,str) else value
    return head(0x60 if isinstance(value,str) else 0x40,len(raw))+raw

class AssertionVerificationTests(unittest.TestCase):
    def setUp(self):
        self.private=ec.generate_private_key(ec.SECP256R1())
        self.pem=self.private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.app='TEAM123456.com.example.risk'
        self.client=hashlib.sha256(b'{"request":"trusted-server-challenge"}').digest()
    def assertion(self,counter=1,app=None,client=None,flags=0):
        auth=hashlib.sha256((app or self.app).encode()).digest()+bytes([flags])+counter.to_bytes(4,'big')
        signature=self.private.sign(auth+(client or self.client),ec.ECDSA(hashes.SHA256()))
        return cbor({'signature':signature,'authenticatorData':auth})
    def test_valid_p256_signature_counter(self):
        self.assertEqual(verify_assertion(self.assertion(7),self.pem,self.app,self.client,6),7)
    def test_replay_wrong_app_key_challenge_rejected(self):
        other=ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        for pem,app,client,previous in [(self.pem,self.app,self.client,1),(other,self.app,self.client,0),(self.pem,'OTHER.com.example.risk',self.client,0),(self.pem,self.app,hashlib.sha256(b'wrong challenge').digest(),0)]:
            with self.subTest(app=app,previous=previous),self.assertRaises(AppAssertionError):verify_assertion(self.assertion(),pem,app,client,previous)
    def test_corruption_trailing_data_and_extensions_rejected(self):
        for assertion in [self.assertion()+b'\x00',self.assertion()[:-1],b'{}',self.assertion(flags=0x80)]:
            with self.assertRaises(AppAssertionError):verify_assertion(assertion,self.pem,self.app,self.client,0)
    def test_unregistered_input_cannot_provide_its_own_key(self):
        with self.assertRaises(AppAssertionError):verify_assertion(self.assertion(),b'',self.app,self.client,0)
    def test_counter_zero_rejected(self):
        with self.assertRaises(AppAssertionError):verify_assertion(self.assertion(0),self.pem,self.app,self.client,0)

class CollectorBindingTests(unittest.TestCase):
    def setUp(self):
        import test_completion_ingress
        self.fixture=test_completion_ingress.IngressCompletionTests()
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
    def test_unbound_account_reference_rejected(self):
        from agent.collector import ingest,enrich_business_event
        ctx=self.fixture.auth('a-sdk');ctx.attributes.pop('account_id')
        ingest(self.fixture.upload(),ctx)
        with self.assertRaises(PermissionError): enrich_business_event({'uid':'stranger','report_ids':['r']},self.fixture.auth('a-business'))
    def test_unknown_field_mapping_rejected(self):
        from agent.collector import ingest
        from agent.contracts.report_contract import signature_input,legacy_mac
        v=self.fixture.upload();v['field_mapping_version']='unknown'
        v['signature']=legacy_mac(bytes(range(32)),signature_input(v))
        with self.assertRaises(ValueError): ingest(v,self.fixture.auth('a-sdk'))
    def test_stale_report_cannot_gain_business_identity(self):
        from agent.collector import ingest,enrich_business_event
        import time
        ingest(self.fixture.upload(),self.fixture.auth('a-sdk'))
        with unittest.mock.patch('agent.collector.time.time',return_value=time.time()+600):
            with self.assertRaises(ValueError): enrich_business_event({'uid':'u','report_ids':['r']},self.fixture.auth('a-business'))

class EnrollmentTests(unittest.TestCase):
    def fixture(self, challenge=None):
        import base64
        from datetime import datetime,timedelta,timezone
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        now=datetime.now(timezone.utc);challenge=challenge or b'server-random-enrollment-1234567890';app='TEAM123456.com.example.risk'
        rootkey=ec.generate_private_key(ec.SECP256R1());interkey=ec.generate_private_key(ec.SECP256R1());leafkey=ec.generate_private_key(ec.SECP256R1())
        def certificate(name,key,issuer,issuer_key,ca,path_length,nonce=None):
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
            b=x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca,path_length),critical=True)
            if nonce:b=b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.840.113635.100.8.2'),b'\x30\x24\xa1\x22\x04\x20'+nonce),critical=False)
            return b.sign(issuer_key,hashes.SHA256())
        root=certificate('SOFTWARE TEST ROOT',rootkey,None,rootkey,True,1)
        inter=certificate('SOFTWARE TEST INTERMEDIATE',interkey,root.subject,rootkey,True,0)
        pub=leafkey.public_key();nums=pub.public_numbers();point=pub.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        kid=hashlib.sha256(point).digest();auth=hashlib.sha256(app.encode()).digest()+b'\x40'+b'\0'*4+b'appattest'+b'\0'*7+b'\0\x20'+kid+cbor({1:2,3:-7,-1:1,-2:nums.x.to_bytes(32,'big'),-3:nums.y.to_bytes(32,'big')})
        nonce=hashlib.sha256(auth+hashlib.sha256(challenge).digest()).digest()
        leaf=certificate('SOFTWARE TEST CREDENTIAL',leafkey,inter.subject,interkey,False,None,nonce)
        raw=cbor({'fmt':'apple-appattest','attStmt':{'x5c':[leaf.public_bytes(serialization.Encoding.DER),inter.public_bytes(serialization.Encoding.DER)],'receipt':b'software-fixture-not-apple-receipt'},'authData':auth})
        return raw,base64.b64encode(kid).decode(),app,challenge,root.public_bytes(serialization.Encoding.PEM),pub.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    def test_trusted_chain_challenge_environment_and_key_binding(self):
        from agent.app_attest import verify_attestation
        raw,kid,app,challenge,root,pem=self.fixture()
        self.assertEqual(verify_attestation(raw,kid,app,challenge,root),pem)
        for kwargs in [dict(challenge=b'wrong-server-challenge-1234567890123'),dict(app_id='OTHER.app'),dict(key_id='AAAA'),dict(environment='development')]:
            args=dict(attestation_bytes=raw,key_id=kid,app_id=app,challenge=challenge,root_pem=root);args.update(kwargs)
            with self.assertRaises(AppAssertionError):verify_attestation(**args)
        wrong_root=self.fixture()[4]
        with self.assertRaises(AppAssertionError):verify_attestation(raw,kid,app,challenge,wrong_root)

class CollectorChallengeTests(unittest.TestCase):
    setUp = CollectorBindingTests.setUp
    def test_challenge_and_counter_commit_atomically(self):
        import base64,json
        from agent.collector import ingest,issue_challenge,_database
        from agent.tenancy import data_context
        from agent.contracts.report_contract import legacy_mac,signature_input
        ctx=self.fixture.auth('a-sdk');private=ec.generate_private_key(ec.SECP256R1())
        pem=self.fixture.root/'public.pem';pem.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        app='TEAM123456.com.example.risk'
        ctx.attributes['attestation_keys']={'ak':{'public_key_file':str(pem),'app_id':app}}
        ctx.attributes['require_hardware_attestation']=True
        challenge=issue_challenge(ctx)
        v=self.fixture.upload();v['attestation_key_id']='ak'
        def assertion(data,counter):
            auth=hashlib.sha256(app.encode()).digest()+b'\0'+counter.to_bytes(4,'big')
            signature=private.sign(auth+hashlib.sha256(data).digest(),ec.ECDSA(hashes.SHA256()))
            return base64.b64encode(cbor({'signature':signature,'authenticatorData':auth})).decode()
        v['attestation_assertion']=assertion(base64.b64decode(v['payload_json']),1)
        v['re_attestation_assertion']=assertion(b'wrong challenge',2)
        v['signature']=legacy_mac(bytes(range(32)),signature_input(v))
        with self.assertRaises(ValueError):ingest(v,ctx)
        with data_context(ctx):
            db=_database()
            self.assertEqual(db.execute('SELECT consumed FROM attestation_challenges').fetchone()[0],0)
            self.assertIsNone(db.execute('SELECT counter FROM attestation_counters').fetchone());db.close()
        v['re_attestation_assertion']=assertion(base64.b64decode(challenge['challenge']),2)
        v['signature']=legacy_mac(bytes(range(32)),signature_input(v))
        self.assertEqual(ingest(v,ctx)['server_attestation'],'verified_assertion')
        self.assertTrue(ingest(v,ctx)['idempotent_replay'])
        with data_context(ctx):
            db=_database()
            self.assertEqual(db.execute('SELECT consumed FROM attestation_challenges').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT counter FROM attestation_counters').fetchone()[0],2);db.close()

    def test_enrollment_consumes_challenge_and_persists_trusted_key(self):
        import test_completion_ingress,base64
        from agent.collector import issue_challenge,register_attestation,_database
        from agent.tenancy import data_context
        f=test_completion_ingress.IngressCompletionTests();f.setUp();self.addCleanup(f.doCleanups)
        ctx=f.auth('a-sdk');challenge=issue_challenge(ctx,'enrollment')
        raw,kid,app,_,root,pem=EnrollmentTests().fixture(base64.b64decode(challenge['challenge']))
        rootfile=f.root/'apple-test-root.pem';rootfile.write_bytes(root)
        ctx.attributes['app_attest_enrollment']={'root_certificate_file':str(rootfile),'app_id':app}
        request={'attestation':base64.b64encode(raw).decode(),'key_id':kid,'challenge_id':challenge['challenge_id']}
        self.assertEqual(register_attestation(request,ctx)['status'],'enrolled')
        with self.assertRaises(ValueError):register_attestation(request,ctx)
        with data_context(ctx):
            db=_database();row=db.execute('SELECT public_key,principal FROM enrolled_attestation_keys').fetchone();db.close()
        self.assertEqual(tuple(row),(pem,ctx.principal))

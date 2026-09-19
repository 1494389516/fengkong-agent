"""Authenticated SDK collector: verify original bytes, then atomically store evidence.

MAC verification authenticates a provisioned installation, never a human or a
fraud label. App Attest is a separate optional server policy and verdict.
"""
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
from pathlib import Path
import time

from .contracts.report_contract import (ContractError, canonical_payload, pseudonymize,
                                       validate_upload, verify_upload_with_base_key)
from .tenancy import data_context


def _database():
    from .tools.online_store import connect
    db=connect()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS report_receipts (
          tenant TEXT, app TEXT, report_id TEXT, digest TEXT NOT NULL,
          evidence_id TEXT NOT NULL, nonce TEXT NOT NULL, principal TEXT NOT NULL,
          receipt TEXT NOT NULL, PRIMARY KEY(tenant,app,report_id),
          UNIQUE(tenant,app,principal,nonce));
        CREATE TABLE IF NOT EXISTS evidence (
          evidence_id TEXT PRIMARY KEY, tenant TEXT, app TEXT, raw_envelope BLOB,
          raw_payload BLOB, raw_digest TEXT, received_at REAL, observation TEXT);
        CREATE TABLE IF NOT EXISTS attestation_counters (
          tenant TEXT, app TEXT, key_id TEXT, counter INTEGER,
          PRIMARY KEY(tenant,app,key_id));
        CREATE TABLE IF NOT EXISTS attestation_challenges (
          challenge_id TEXT PRIMARY KEY,tenant TEXT,app TEXT,principal TEXT,purpose TEXT,
          challenge BLOB,expires_at REAL,consumed INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS enrollment_evidence (
          tenant TEXT,app TEXT,key_id TEXT,attestation BLOB,received_at REAL,
          PRIMARY KEY(tenant,app,key_id));
        CREATE TABLE IF NOT EXISTS enrolled_attestation_keys (
          tenant TEXT,app TEXT,key_id TEXT,principal TEXT,public_key BLOB,app_id TEXT,
          PRIMARY KEY(tenant,app,key_id));
    ''')
    return db


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                    ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def _finite_payload(value, depth=0):
    if depth>16: raise ContractError('payload nesting budget exceeded')
    if isinstance(value,float) and not math.isfinite(value): raise ContractError('nonfinite payload')
    if isinstance(value,int) and value.bit_length()>1024: raise ContractError('oversize payload integer')
    if isinstance(value,dict):
        for item in value.values(): _finite_payload(item,depth+1)
    if isinstance(value,list):
        for item in value: _finite_payload(item,depth+1)


def ingest(upload, context, *, wire_bytes=None, remote_ip=None, now=None):
    context.require('reports.write')
    now=time.time() if now is None else now
    attrs=context.attributes
    required=bool(attrs.get('require_hardware_attestation',False))
    value=validate_upload(upload,require_hardware=required)
    if value['sig_ver'] not in ('v2','v2h','v3'):
        raise ContractError('collector does not permit this signature version')
    if (value['app_id']!=context.app or value['device_id']!=attrs.get('subject')
            or value['key_id'] not in attrs.get('key_ids',())):
        raise PermissionError('report is not bound to this credential')
    if not hmac.compare_digest(hashlib.sha256(value['session_token'].encode()).hexdigest(),attrs.get('session_sha256','')):
        raise PermissionError('report session is not authorized')
    keys=json.loads(Path(os.environ['FK_COLLECTOR_KEYS']).read_text())
    key=base64.b64decode(keys[value['key_id']],validate=True)
    if len(key)<32 or not verify_upload_with_base_key(value,key,require_hardware=required):
        raise ContractError('invalid report MAC')
    raw_payload=base64.b64decode(value['payload_json'],validate=True)
    payload=json.loads(canonical_payload(raw_payload))
    _finite_payload(payload)
    mapping=value.get('field_mapping_version','')
    mappings=attrs.get('field_mappings',{})
    digest=_digest(value)
    # Server-owned namespace key never leaves Collector.
    identity_key=Path(os.environ['FK_IDENTITY_KEY_FILE']).read_bytes()
    generation=str(attrs.get('generation',''))
    if not generation: raise PermissionError('installation generation is not registered')
    entity=pseudonymize(identity_key,tenant=context.tenant,app=context.app,
        domain='installation',key_version=str(attrs.get('identity_key_version','1')),
        value=json.dumps([attrs['subject'],generation],separators=(',',':')))
    with data_context(context):
        db=_database()
        try:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT digest,receipt FROM report_receipts WHERE tenant=? AND app=? AND report_id=?',
                (context.tenant,context.app,value['report_id'])).fetchone()
            if old:
                if old[0]!=digest: raise ContractError('report id content conflict')
                result=json.loads(old[1]);result['idempotent_replay']=True
                db.rollback();return result
            if abs(now-value['ts']/1000)>300:
                raise ContractError('report timestamp outside accepted freshness window')
            if db.execute('SELECT 1 FROM report_receipts WHERE tenant=? AND app=? AND principal=? AND nonce=?',
                          (context.tenant,context.app,context.principal,value['nonce'])).fetchone():
                raise ContractError('nonce reused with different report')
            verdict='not_present'
            if value.get('attestation_assertion'):
                from .app_attest import verify_assertion
                att_id=value.get('attestation_key_id')
                enrolled=db.execute('SELECT public_key,app_id,principal FROM enrolled_attestation_keys WHERE tenant=? AND app=? AND key_id=?',
                    (context.tenant,context.app,att_id)).fetchone()
                if enrolled:
                    if enrolled[2]!=context.principal: raise ContractError('attestation key principal mismatch')
                    pem,apple_app_id=enrolled[:2]
                else:
                    attestation=attrs.get('attestation_keys',{}).get(att_id)
                    if not attestation: raise ContractError('attestation key is not enrolled')
                    pem=Path(attestation['public_key_file']).read_bytes();apple_app_id=attestation['app_id']
                previous=db.execute('SELECT counter FROM attestation_counters WHERE tenant=? AND app=? AND key_id=?',
                                    (context.tenant,context.app,att_id)).fetchone()
                # Primary SDK assertion signs payload; separate assertion proves fresh server challenge.
                client_hash=hashlib.sha256(raw_payload).digest()
                count=verify_assertion(base64.b64decode(value['attestation_assertion']),
                    pem,apple_app_id,
                    client_hash,previous[0] if previous else 0)
                challenge=db.execute('SELECT challenge_id,challenge FROM attestation_challenges WHERE tenant=? AND app=? AND principal=? AND purpose=? AND consumed=0 AND expires_at>? ORDER BY expires_at DESC LIMIT 1',
                    (context.tenant,context.app,context.principal,'assertion',now)).fetchone()
                if not challenge or not value.get('re_attestation_assertion'):
                    raise ContractError('fresh server challenge assertion required')
                count=verify_assertion(base64.b64decode(value['re_attestation_assertion'],validate=True),pem,apple_app_id,
                    hashlib.sha256(challenge[1]).digest(),count)
                db.execute('UPDATE attestation_challenges SET consumed=1 WHERE challenge_id=? AND consumed=0',(challenge[0],))
                db.execute('INSERT OR REPLACE INTO attestation_counters VALUES(?,?,?,?)',
                           (context.tenant,context.app,att_id,count))
                verdict='verified_assertion'
            if required and verdict!='verified_assertion': raise ContractError('required hardware verification missing')
            from .sdk_payload import restore_fields, decode_detection, decoder_provenance
            payload=restore_fields(payload,mapping,mappings,value['ts'])
            detection=decode_detection(payload,value)
            # Whitelist observation fields. In particular payload server/sr/aggregate
            # claims and self-reported trust never enter server feature state.
            hardware=payload.get('hardware_attributes',{})
            if detection['status']=='decoded':
                device=payload.get('dv',{})
                hardware={target:device[key] for key,target in
                    (('m','model'),('sv','os_version'),('sw','screen_width'),('sh','screen_height'))
                    if key in device} if isinstance(device,dict) else {}
            hardware={k:v for k,v in hardware.items() if k in ('model','os_version','cpu_count','memory_gb','screen_width','screen_height')
                      and isinstance(v,(str,int,float)) and not isinstance(v,bool)} if isinstance(hardware,dict) else {}
            evidence_id=hashlib.sha256((context.tenant+'\0'+context.app+'\0'+digest).encode()).hexdigest()
            observation={'evidence_id':evidence_id,'report_id':value['report_id'],
                'tenant_id':context.tenant,'app_id':context.app,'uid':attrs.get('account_id'),
                'device_id':entity,'entity_generation':generation,'identity_trust':'server_bound',
                'hardware_attributes':hardware,'observed_at':value['ts']/1000,'recorded_at':now,
                'source_kind':'sdk_observation','verification':'verified_mac','server_attestation':verdict,
                'sdk_detection':detection,'decode_provenance':decoder_provenance(mapping,mappings),
                'measurement_status':'observed','evidence_digest':hashlib.sha256(raw_payload).hexdigest()}
            if remote_ip: observation['ip']=remote_ip
            receipt={'report_id':value['report_id'],'evidence_id':evidence_id,'verification':'verified_mac',
                     'server_attestation':verdict,'received_at':now,'idempotent_replay':False}
            envelope_bytes=wire_bytes if wire_bytes is not None else json.dumps(value,ensure_ascii=False,allow_nan=False).encode()
            db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)',(evidence_id,context.tenant,context.app,
                envelope_bytes,raw_payload,hashlib.sha256(envelope_bytes).hexdigest(),now,json.dumps(observation)))
            db.execute('INSERT INTO report_receipts VALUES(?,?,?,?,?,?,?,?)',(context.tenant,context.app,
                value['report_id'],digest,evidence_id,value['nonce'],context.principal,json.dumps(receipt)))
            db.commit();return receipt
        except BaseException:
            db.rollback();raise
        finally:
            db.close()


def get_observation(evidence_id, context):
    context.require('cases.read')
    with data_context(context):
        db=_database()
        try:
            row=db.execute('SELECT observation FROM evidence WHERE evidence_id=? AND tenant=? AND app=?',
                           (evidence_id,context.tenant,context.app)).fetchone()
            if not row: raise PermissionError('evidence not in authorized domain')
            return json.loads(row[0])
        finally:
            db.close()


def enrich_business_event(event, context, connection=None):
    context.require('decisions.write')
    refs=event.get('report_ids',[])
    if not isinstance(refs,list) or len(refs)>32 or any(not isinstance(r,str) or not r for r in refs):
        raise ContractError('report_ids must be a bounded list')
    result=dict(event);observations=[]
    with data_context(context):
        db=connection if connection is not None else _database()
        try:
            if refs and connection is not None:
                tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {"report_receipts", "evidence"}.issubset(tables):
                    raise PermissionError("report reference is outside this domain")
            for report_id in refs:
                row=db.execute('SELECT e.observation FROM report_receipts r JOIN evidence e ON r.evidence_id=e.evidence_id '
                    'WHERE r.tenant=? AND r.app=? AND r.report_id=?',(context.tenant,context.app,report_id)).fetchone()
                if not row: raise PermissionError('report reference is outside this domain')
                obs=json.loads(row[0])
                if not obs.get('uid') or obs['uid']!=event.get('uid'):
                    raise PermissionError('report account binding mismatch')
                if not 0 <= time.time()-obs['recorded_at'] <= 300:
                    raise ContractError('report reference outside freshness window')
                event_time=event.get('ts',time.time())
                if type(event_time) not in (int,float) or not math.isfinite(event_time) or abs(event_time-obs['observed_at'])>300:
                    raise ContractError('report/event time mismatch')
                observations.append(obs)
        finally:
            if connection is None: db.close()
    if observations:
        identities={o['device_id'] for o in observations}
        if len(identities)!=1: raise ContractError('mixed installation reports require investigation')
        latest=max(observations,key=lambda o:o['recorded_at'])
        for field in ('device_id','entity_generation','identity_trust','hardware_attributes'):
            result[field]=latest[field]
        result['evidence_refs']=[o['evidence_id'] for o in observations]
    else:
        result['identity_trust']='asserted'
        result['evidence_refs']=[]
    return result


def issue_challenge(context, purpose='assertion', *, now=None):
    context.require('reports.write')
    if purpose not in ('assertion','enrollment'): raise ContractError('invalid challenge purpose')
    now=time.time() if now is None else now
    challenge=secrets.token_bytes(32);identifier=secrets.token_urlsafe(24)
    with data_context(context):
        db=_database()
        try:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE attestation_challenges SET consumed=1 WHERE tenant=? AND app=? AND principal=? AND purpose=?',
                (context.tenant,context.app,context.principal,purpose))
            db.execute('INSERT INTO attestation_challenges VALUES(?,?,?,?,?,?,?,0)',
                (identifier,context.tenant,context.app,context.principal,purpose,challenge,now+120))
            db.commit()
        finally: db.close()
    return {'challenge_id':identifier,'challenge':base64.b64encode(challenge).decode(),'expires_at':now+120,'purpose':purpose}


def register_attestation(value, context, *, now=None):
    """Enroll only an Apple-root-validated key bound to this live server challenge."""
    context.require('reports.write')
    from .app_attest import verify_attestation
    now=time.time() if now is None else now
    cfg=context.attributes.get('app_attest_enrollment',{})
    if not cfg.get('root_certificate_file') or not cfg.get('app_id'):
        raise ContractError('trusted Apple enrollment configuration missing')
    with data_context(context):
        db=_database()
        try:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT challenge FROM attestation_challenges WHERE challenge_id=? AND tenant=? AND app=? AND principal=? AND purpose=? AND consumed=0 AND expires_at>?',
                (value.get('challenge_id'),context.tenant,context.app,context.principal,'enrollment',now)).fetchone()
            if not row: raise ContractError('enrollment challenge missing expired or consumed')
            pem=verify_attestation(base64.b64decode(value['attestation'],validate=True),value['key_id'],cfg['app_id'],row[0],
                Path(cfg['root_certificate_file']).read_bytes(),environment=cfg.get('environment','production'),now=now)
            previous=db.execute('SELECT principal FROM enrolled_attestation_keys WHERE tenant=? AND app=? AND key_id=?',
                (context.tenant,context.app,value['key_id'])).fetchone()
            if previous: raise ContractError('attestation key already enrolled')
            db.execute('INSERT INTO enrolled_attestation_keys VALUES(?,?,?,?,?,?)',
                (context.tenant,context.app,value['key_id'],context.principal,pem,cfg['app_id']))
            db.execute('INSERT INTO enrollment_evidence VALUES(?,?,?,?,?)',
                (context.tenant,context.app,value['key_id'],base64.b64decode(value['attestation'],validate=True),now))
            db.execute('UPDATE attestation_challenges SET consumed=1 WHERE challenge_id=?',(value['challenge_id'],))
            db.commit();return {'key_id':value['key_id'],'status':'enrolled'}
        except BaseException: db.rollback();raise
        finally: db.close()

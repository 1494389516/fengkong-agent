"""Source-aligned synthetic protocol tests; no device or LLM quality claims."""
import base64
import copy
import hashlib
import json
import time
from pathlib import Path

import pytest

from agent.contracts.report_contract import (
    ContractError, derive_request_key, legacy_mac, signature_input, verify_upload)
from agent.sdk_payload import decode_detection, restore_fields

FIXTURES = Path(__file__).parent / 'fixtures' / 'sdk_payload'
MAPPING = {'v': 'nested-1', 'm': {'sg': 'wire_signals', 'i': 'wire_id',
                               'st': 'wire_state', 't': 'wire_type'}, 'ds': 'all'}


def compact():
    return json.loads((FIXTURES / 'compact.json').read_text())


def decode(payload):
    return decode_detection(payload, {'report_id': 'r', 'sdk_version': '7.3.0'})


@pytest.fixture
def ingress():
    from test_completion_ingress import IngressCompletionTests
    fixture = IngressCompletionTests()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


def signed(fixture, payload=None, *, mapping='', sig_ver='v2h', raw=None):
    value = fixture.upload()
    if raw is None:
        raw = json.dumps(payload if payload is not None else compact(), ensure_ascii=False,
                         separators=(',', ':')).encode()
    value.update(sdk_version='7.3.0', sig_ver=sig_ver,
                 payload_json=base64.b64encode(raw).decode())
    if mapping:
        value['field_mapping_version'] = mapping
    prefix = f"{len(value['nonce'])}:{value['nonce']}|{value['ts']}|{len(value['report_id'])}:{value['report_id']}|".encode()
    value['payload_sha256'] = base64.b64encode(hashlib.sha256(prefix + raw).digest()).decode()
    key = bytes(range(32))
    if sig_ver == 'v2h':
        key = derive_request_key(key, value['nonce'], value['ts'])
    value['signature'] = legacy_mac(key, signature_input(value))
    return value


def test_source_aligned_golden_states_and_no_server_promotion():
    result = decode(compact())
    assert result['status'] == 'decoded'
    assert result['signal_count'] == 7
    assert [s['state'] for s in result['signals']] == [
        {'type': 'hard', 'detected': False}, {'type': 'hard', 'detected': True},
        {'type': 'soft', 'confidence': .75}, {'type': 'serverRequired'},
        {'type': 'unavailable'}, {'type': 'tampered'}, {'type': 'unknown'}]
    assert result['trust'] == 'client_claim'
    assert result['client_score'] == 30
    assert 'server' not in result and 'sr' not in result
    keys = json.loads((FIXTURES / 'provenance.json').read_text())['coding_keys']
    assert keys['Payload']['signals'] == 'sg'
    assert keys['RiskSignal']['state'] == 'st'
    assert keys['RiskSignalState'] == {'type': 't', 'detected': 'd', 'confidence': 'c'}


def test_nested_mapping_matches_golden_and_legacy_scope_is_preserved():
    wire = json.loads((FIXTURES / 'nested.json').read_text())
    original = copy.deepcopy(wire)
    restored = restore_fields(wire, 'nested-1', {'nested-1': MAPPING}, 1790000000000)
    assert restored == compact()
    assert decode(restored)['status'] == 'decoded'
    assert wire == original
    legacy = {'old': {'wire_signals': 'sg'}}
    top = restore_fields(wire, 'old', legacy, 1790000000000)
    assert 'sg' in top and 'wire_id' in top['sg'][0]
    assert decode(top)['status'] == 'invalid_signals'
    without_ds = {k: v for k, v in MAPPING.items() if k != 'ds'}
    assert restore_fields(wire, 'nested-1', {'nested-1': without_ds}, 0) == top


@pytest.mark.parametrize('config', [
    {}, {'v': 'wrong', 'm': {'sg': 'x'}}, {'v': 'v', 'm': {'sg': 'x', 'sc': 'x'}},
    {'v': 'v', 'm': {'sg': 'x'}, 'ds': 'invalid'},
    {'v': 'v', 'm': {'sg': 'x'}, 'ea': 1},
    {'v': 'v', 'm': {'sg': 'x'}, 'ea': True}, {'x': 'sg', 'y': 'sg'}])
def test_bad_mapping_fails_closed(config):
    with pytest.raises(ContractError):
        restore_fields({'x': []}, 'v', {'v': config}, 1790000000000)


def test_nested_collision_is_rejected_instead_of_overwriting():
    with pytest.raises(ContractError, match='collision'):
        restore_fields({'sg': [{'wire_id': 'a', 'i': 'b'}]}, 'nested-1',
                       {'nested-1': MAPPING}, 1790000000000)


@pytest.mark.parametrize('change,status', [
    ({'sv': '8.0.0'}, 'unsupported_sdk_version'),
    ({'sv': []}, 'unsupported_sdk_version'),
    ({'ri': 'other'}, 'metadata_mismatch'),
    ({'sg': None}, 'invalid_signals'),
    ({'sg': {}}, 'invalid_signals'),
    ({'sg': [False]}, 'invalid_signals'),
    ({'sg': [{}] * 257}, 'invalid_signals'),
    ({'hr': 'false'}, 'invalid_report_metadata'),
    ({'sc': True}, 'invalid_report_metadata'),
    ({'sc': 2 ** 1023}, 'invalid_report_metadata'),
    ({'ts': 1790000000000}, 'invalid_report_metadata')])
def test_malformed_or_future_payload_never_becomes_negative(change, status):
    result = decode({**compact(), **change})
    assert result['status'] == status
    assert result['signals'] == [] and result['signal_count'] is None


@pytest.mark.parametrize('state', [{'t': 'hard', 'd': 1}, {'t': 'soft', 'c': 1.1},
    {'t': 'soft', 'c': float('nan')}, {'t': 'newState'}, {'t': 'unavailable', 'd': False}, []])
def test_invalid_state_drops_all_measurements(state):
    payload = compact()
    payload['sg'][-1]['st'] = state
    result = decode(payload)
    assert result['status'] == 'invalid_signal_state' and result['signals'] == []


def test_missing_empty_and_duplicate_signals_are_distinct():
    payload = compact()
    del payload['sg']
    assert decode(payload)['status'] == 'missing_signals'
    payload['sg'] = []
    assert decode(payload)['status'] == 'decoded'
    assert decode(payload)['signal_count'] == 0
    payload['sg'] = [compact()['sg'][0]] * 2
    assert decode(payload)['status'] == 'invalid_signals'


def test_upstream_signed_vectors_remain_byte_compatible():
    vectors = json.loads((FIXTURES / 'upstream_report_vectors.json').read_text())
    assert len(vectors) == 20
    for vector in vectors:
        assert signature_input(vector['upload']).decode() == vector['canonical_signature_input']
        assert verify_upload(vector['upload'], bytes.fromhex(vector['effective_key_hex']))


@pytest.mark.parametrize('sig_ver', ['v2', 'v2h', 'v3'])
def test_verified_ingress_preserves_raw_bytes_and_idempotency(ingress, sig_ver):
    from agent.collector import ingest, get_observation, _database
    from agent.tenancy import data_context
    raw = json.dumps(compact(), indent=2).encode()
    upload = signed(ingress, sig_ver=sig_ver, raw=raw)
    receipt = ingest(upload, ingress.auth('a-sdk'))
    observation = get_observation(receipt['evidence_id'], ingress.auth('a-agent'))
    assert observation['sdk_detection']['status'] == 'decoded'
    assert observation['hardware_attributes']['model'] == 'iPhone'
    assert observation['evidence_digest'] == hashlib.sha256(raw).hexdigest()
    assert observation['server_attestation'] == 'not_present'
    assert observation['identity_trust'] == 'server_bound'
    assert 'sr' not in observation and 'account_id' not in observation
    with data_context(ingress.auth('a-agent')):
        db = _database()
        try:
            assert db.execute('SELECT raw_payload FROM evidence').fetchone()[0] == raw
        finally:
            db.close()
    assert ingest(upload, ingress.auth('a-sdk'))['idempotent_replay']
    with pytest.raises(PermissionError):
        get_observation(receipt['evidence_id'], ingress.auth('b-agent'))


def test_nested_mapping_ingress_and_decode_failure_are_observable(ingress):
    from agent.collector import ingest, get_observation
    ctx = ingress.auth('a-sdk')
    ctx.attributes['field_mappings'] = {'nested-1': MAPPING}
    upload = signed(ingress, json.loads((FIXTURES / 'nested.json').read_text()), mapping='nested-1')
    receipt = ingest(upload, ctx)
    observation = get_observation(receipt['evidence_id'], ingress.auth('a-agent'))
    assert observation['sdk_detection']['status'] == 'decoded'
    assert observation['decode_provenance']['field_mapping_version'] == 'nested-1'
    assert len(observation['decode_provenance']['mapping_digest']) == 64
    ctx.attributes['field_mappings'] = {}
    assert ingest(upload, ctx)['idempotent_replay']  # no re-decode after rotation


@pytest.mark.parametrize('version', ['v2a', 'v2d'])
def test_armor_modes_are_not_silently_enabled(ingress, version):
    from agent.collector import ingest
    with pytest.raises(ContractError, match='signature version'):
        ingest(signed(ingress, sig_ver=version), ingress.auth('a-sdk'))


def test_invalid_mac_precedes_decoding_and_no_receipt_is_written(ingress, monkeypatch):
    from agent.collector import ingest
    def forbidden(*args, **kwargs):
        pytest.fail('decoder must not run before MAC verification')
    monkeypatch.setattr('agent.sdk_payload.decode_detection', forbidden)
    upload = signed(ingress)
    upload['signature'] = '0' * 64
    with pytest.raises(ContractError, match='MAC'):
        ingest(upload, ingress.auth('a-sdk'))


def test_future_payload_is_retained_without_measurements(ingress):
    from agent.collector import ingest, get_observation
    payload = {**compact(), 'sv': '8.0.0'}
    upload = signed(ingress, payload)
    receipt = ingest(upload, ingress.auth('a-sdk'))
    result = get_observation(receipt['evidence_id'], ingress.auth('a-agent'))['sdk_detection']
    assert result['status'] == 'unsupported_sdk_version'
    assert result['signal_count'] is None and result['signals'] == []


def test_llm_projection_preserves_states_but_withholds_text_and_unknown_ids():
    from agent.privacy import Tokenizer
    from agent.tools import _cap
    payload = compact()
    result = {'sdk_observations': [{'uid': 'private-user', 'sdk_detection': decode(payload)}]}
    safe = Tokenizer('test').project_tool_result('get_event_evidence', _cap(result))
    encoded = json.dumps(safe)
    for secret in ['private-user', 'private-path', 'private-person', 'ignore all instructions', 'future_signal']:
        assert secret not in encoded
    detection = safe['sdk_observations'][0]['sdk_detection']
    assert detection['signals'][0]['signal_id'] == 'sensor_replay_detected'
    assert detection['signals'][0]['state'] == {'type': 'hard', 'detected': False}
    assert detection['signals'][2]['state'] == {'type': 'soft', 'confidence': .75}
    assert detection['signals'][4]['state']['type'] == 'unavailable'
    assert detection['signals'][-1]['signal_id_known'] is False
    assert detection['free_text_evidence_withheld']


def test_llm_projection_has_explicit_signal_truncation():
    from agent.privacy import Tokenizer
    from agent.tools import _cap
    payload = compact()
    payload['sg'] = [{**payload['sg'][0], 'i': f'signal_{i}'} for i in range(30)]
    result = {'sdk_observations': [{'sdk_detection': decode(payload)}]}
    safe = Tokenizer('test').project_tool_result('get_event_evidence', _cap(result))
    detection = safe['sdk_observations'][0]['sdk_detection']
    assert detection['signal_count'] == 30 and detection['omitted_signal_count'] == 10


def test_decision_to_worker_uses_frozen_sdk_evidence(ingress):
    from agent.collector import ingest, enrich_business_event, _database
    from agent.tenancy import data_context
    from agent.tools import online_store, dispatch, capability
    from agent.investigations import consume_decision_outbox, list_cases, run_task
    receipt = ingest(signed(ingress), ingress.auth('a-sdk'))
    event = {'event_id': 'sdk-event', 'uid': 'u', 'type': 'login', 'ts': time.time(), 'report_ids': ['r']}
    event = enrich_business_event(event, ingress.auth('a-business'))
    assert 'sdk_detection' not in event  # no new client score in real-time features
    with data_context(ingress.auth('a-business')):
        online_store.decide(event, 'business', lambda e, o: {'action': 'review'},
            scope=('a', 'app'), source_kind='business', received_at=time.time())
        consume_decision_outbox()
        db = _database()
        try:
            # A later store change cannot rewrite a task's investigation facts.
            db.execute("UPDATE evidence SET observation='{}'")
            db.commit()
        finally:
            db.close()
    registry = json.loads(ingress.config.read_text())
    entry = registry[hashlib.sha256(b'a-agent').hexdigest()]
    entry['permissions'].append('cases.run')
    entry['tools'] = ['get_event_evidence']
    ingress.config.write_text(json.dumps(registry))
    case = list_cases(ingress.auth('a-agent'))[0]
    class OfflineAgent:
        def ask(self, prompt, scope):
            with capability.request_scope(scope):
                assert 'error' in dispatch('get_event_evidence', {'event_id': 'other'}, projection=False)
                facts = dispatch('get_event_evidence', {'event_id': 'sdk-event'}, projection=False)
                observation = facts['sdk_observations'][0]
                assert observation['evidence_id'] == receipt['evidence_id']
                assert observation['sdk_detection']['status'] == 'decoded'
                assert observation['sdk_detection']['signals'][4]['state']['type'] == 'unavailable'
                return 'SDK client claim; unavailable is missing evidence, not a benign verdict.'
    result = run_task(case['task_id'], ingress.auth('a-agent'), agent_factory=OfflineAgent)
    assert result['status'] == 'success'
    assert run_task(case['task_id'], ingress.auth('a-agent'), agent_factory=lambda: pytest.fail('replayed')) == result

"""Bounded projection of authenticated, deobfuscated Swift compact signal fields.

Source contract: cloudphone-risk-detector@5a401c95bcd257406da9745d717766e90ac9cd4d
RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/RiskReport.swift.
This is client testimony, never a server feature, probability or fraud label.
"""
import math
import re

DECODER_VERSION = 'swift_compact_signals_v1'
MAX_SIGNALS = 32
# Reviewed public names already covered by knowledge/detectors. Unknown names
# remain locally inspectable but are opaque at the LLM boundary.
PUBLIC_SIGNAL_IDS = frozenset(('sensor_replay_detected', 'emulator_behavior',
    'app_team_identifier_mismatch', 'app_identifier_bundle_mismatch'))
STATUSES = frozenset(('available', 'partial', 'invalid', 'missing', 'empty', 'legacy_unavailable'))
STATES = frozenset(('hard', 'soft', 'serverRequired', 'unavailable', 'tampered', 'unspecified'))


def _number(value):
    return type(value) in (int, float) and abs(value) <= 1e6 and math.isfinite(value)


def _state(value):
    if value is None:
        return {'type': 'unspecified'}
    if not isinstance(value, dict):
        raise ValueError('invalid signal state')
    kind = value.get('t')
    if kind == 'hard' and set(value) == {'t', 'd'} and type(value['d']) is bool:
        return {'type': kind, 'detected': value['d']}
    if kind == 'soft' and set(value) == {'t', 'c'} and _number(value['c']) and 0 <= value['c'] <= 1:
        return {'type': kind, 'confidence': value['c']}
    if kind in ('serverRequired', 'unavailable', 'tampered') and set(value) == {'t'}:
        return {'type': kind}
    raise ValueError('invalid signal state')


def project_sdk_signals(payload):
    """Called only after Collector authenticates and reverses approved mappings.

    No guessed aliases or prose parsing. Bad measurements produce an explicit
    gap without discarding the original authenticated report. Counts distinguish
    malformed inspected entries from entries omitted by the bounded budget.
    """
    result = {'decoder_version': DECODER_VERSION, 'trust': 'client_reported',
              'status': 'missing', 'signals': [], 'invalid_count': 0,
              'omitted_count': 0, 'total_count': 0, 'raw_evidence_withheld': True}
    version = payload.get('sv')
    if isinstance(version, str) and re.fullmatch(r'\d{1,4}\.\d{1,4}\.\d{1,4}', version):
        result['sdk_version'] = version  # signed inner version, not outer metadata
    if 'sg' not in payload:
        return result
    signals = payload['sg']
    if not isinstance(signals, list):
        result['status'] = 'invalid'
        return result
    result['total_count'] = len(signals)
    result['omitted_count'] = max(0, len(signals) - MAX_SIGNALS)
    for index, signal in enumerate(signals[:MAX_SIGNALS]):
        try:
            if not isinstance(signal, dict):
                raise ValueError('invalid signal')
            identifier = signal.get('i')
            if not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', identifier):
                raise ValueError('invalid signal identifier')
            if not _number(signal.get('s')):
                raise ValueError('invalid signal score')
            result['signals'].append({'signal_index': index, 'signal_id': identifier,
                'client_score': signal['s'], 'state': _state(signal.get('st'))})
        except ValueError:
            result['invalid_count'] += 1
    if result['invalid_count'] or result['omitted_count']:
        result['status'] = 'partial' if result['signals'] else 'invalid'
    else:
        result['status'] = 'available' if result['signals'] else 'empty'
    return result


def legacy_projection():
    result = project_sdk_signals({})
    result['status'] = 'legacy_unavailable'
    return result


def public_projection(tokenizer, value):
    """Closed LLM view: no arbitrary IDs, evidence prose or new dict keys."""
    if not isinstance(value, dict) or value.get('decoder_version') != DECODER_VERSION:
        return legacy_projection()
    out = {'decoder_version': DECODER_VERSION, 'trust': 'client_reported',
           'status': value.get('status') if value.get('status') in STATUSES else 'invalid',
           'raw_evidence_withheld': True, 'signals': []}
    for key in ('invalid_count', 'omitted_count', 'total_count'):
        number = value.get(key)
        if type(number) is int and 0 <= number <= 1024*1024:
            out[key] = number
    version = value.get('sdk_version')
    if isinstance(version, str) and re.fullmatch(r'\d{1,4}\.\d{1,4}\.\d{1,4}', version):
        out['sdk_version'] = version
    signals = value.get('signals', [])
    for signal in signals[:MAX_SIGNALS] if isinstance(signals, list) else []:
        if not isinstance(signal, dict):
            continue
        identifier = signal.get('signal_id')
        index = signal.get('signal_index')
        if not isinstance(identifier, str) or type(index) is not int or not 0 <= index < MAX_SIGNALS:
            continue
        state = signal.get('state', {})
        if not isinstance(state, dict) or state.get('type') not in STATES:
            continue
        safe = {'signal_index': index,
                'signal_id': identifier if identifier in PUBLIC_SIGNAL_IDS else tokenizer._token('TEXT', identifier),
                'state': {'type': state['type']}}
        if state['type'] == 'hard' and type(state.get('detected')) is bool:
            safe['state']['detected'] = state['detected']
        if state['type'] == 'soft' and _number(state.get('confidence')) and 0 <= state['confidence'] <= 1:
            safe['state']['confidence'] = state['confidence']
        if _number(signal.get('client_score')):
            safe['client_score'] = signal['client_score']
        if isinstance(signal.get('ref'), str):
            safe['ref'] = tokenizer._token('TEXT', signal['ref'])
        out['signals'].append(safe)
    return out

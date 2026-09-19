"""Bounded projection of authenticated SDK JSON, never a server fraud verdict.

Wire keys are pinned to cloudphone-risk-detector c481b109 (SDK 7.3.0).
Only call after envelope verification. Raw bytes remain in Collector evidence.
"""
import hashlib
import json
import math

from .contracts.report_contract import ContractError

DECODER_VERSION = 'sdk-compact-1'
SUPPORTED_VERSIONS = frozenset(('7.3.0',))
MAX_SIGNALS = 256


def restore_fields(payload, version, configurations, timestamp_ms):
    """SDK config {v,m,ds,ea}: m maps input wire keys to obfuscated keys.

    Legacy Collector flat tables remain wire->restored, top-level only.
    No mapping/key is ever taken from the uploaded payload itself.
    """
    if not version:
        return payload
    config = configurations.get(version)
    if not isinstance(config, dict) or not config:
        raise ContractError('unsupported field mapping version')
    if isinstance(config.get('m'), dict):
        if set(config) - {'v', 'm', 'ds', 'ea'} or config.get('v') != version:
            raise ContractError('invalid field mapping configuration')
        table = config['m']
        scope = config.get('ds', 'topLevel')
        expiry = config.get('ea')
        if expiry is not None and (type(expiry) is not int or timestamp_ms > expiry):
            raise ContractError('expired field mapping configuration')
        reverse = True
    else:
        table, scope, reverse = config, 'topLevel', False
    if (scope not in ('topLevel', 'all') or len(table) > 1024 or not table
            or any(not isinstance(k, str) or not k or len(k) > 256
                   or not isinstance(v, str) or not v or len(v) > 256 for k, v in table.items())
            or len(set(table.values())) != len(table)):
        raise ContractError('invalid field mapping configuration')
    mapping = {v: k for k, v in table.items()} if reverse else table

    def walk(value, depth=0):
        if depth > 16:
            raise ContractError('payload nesting budget exceeded')
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                target = mapping.get(key, key) if scope == 'all' or depth == 0 else key
                if target in result:
                    raise ContractError('field mapping collision')
                result[target] = walk(item, depth + 1)
            return result
        if isinstance(value, list):
            return [walk(item, depth + 1) for item in value]
        return value

    return walk(payload)


def _number(value, lower, upper):
    return type(value) in (int, float) and lower <= value <= upper and math.isfinite(value)


def _text(value, maximum=128):
    return isinstance(value, str) and 0 < len(value) <= maximum


def decode_detection(payload, upload):
    """Return explicit unknown/invalid states; never synthesize a negative signal.

    A malformed or future payload remains receipt evidence, but yields no usable
    detection measurements. All signals are validated before any are published.
    """
    result = {'decoder_version': DECODER_VERSION, 'status': 'unsupported_schema',
              'trust': 'client_claim', 'signals': [], 'signal_count': None}
    if not any(k in payload for k in ('sv', 'ri', 'sg')):
        return result
    if not isinstance(payload.get('sv'), str) or payload['sv'] not in SUPPORTED_VERSIONS:
        result['status'] = 'unsupported_sdk_version'
        return result
    result['sdk_version'] = payload['sv']
    if payload.get('ri') != upload['report_id'] or payload['sv'] != upload['sdk_version']:
        result['status'] = 'metadata_mismatch'
        return result
    if 'sg' not in payload:
        result['status'] = 'missing_signals'
        return result
    signals = payload['sg']
    if not isinstance(signals, list) or len(signals) > MAX_SIGNALS:
        result['status'] = 'invalid_signals'
        return result
    decoded, ids = [], set()
    for signal in signals:
        if not isinstance(signal, dict):
            result['status'] = 'invalid_signals'
            return result
        identifier, category = signal.get('i'), signal.get('ca')
        evidence = signal.get('ev')
        if (not _text(identifier) or identifier in ids or not _text(category)
                or not _number(signal.get('s'), 0, 100)
                or not isinstance(evidence, dict) or len(evidence) > 64
                or any(not _text(k) or not isinstance(v, str) or len(v) > 4096 for k, v in evidence.items())
                or ('l' in signal and signal['l'] is not None and
                    (type(signal['l']) is not int or not 0 <= signal['l'] <= 100))
                or not _number(signal.get('wh', 0), -10000, 10000)):
            result['status'] = 'invalid_signals'
            return result
        ids.add(identifier)
        state = signal.get('st')
        normalized = {'type': 'unknown'}
        if state is not None:
            if not isinstance(state, dict) or state.get('t') not in (
                    'hard', 'soft', 'serverRequired', 'unavailable', 'tampered'):
                result['status'] = 'invalid_signal_state'
                return result
            kind = state['t']
            allowed = {'t', 'd'} if kind == 'hard' else {'t', 'c'} if kind == 'soft' else {'t'}
            if set(state) - allowed or (kind == 'hard' and type(state.get('d')) is not bool) or (
                    kind == 'soft' and not _number(state.get('c'), 0, 1)):
                result['status'] = 'invalid_signal_state'
                return result
            normalized = {'type': kind}
            if kind == 'hard':
                normalized['detected'] = state['d']
            if kind == 'soft':
                normalized['confidence'] = state['c']
        # Preserve free text only locally. The LLM projection withholds it.
        decoded.append({'signal_id': identifier, 'category': category,
                        'client_score': signal['s'], 'state': normalized,
                        'evidence': dict(evidence), 'layer': signal.get('l')})
    if (not _number(payload.get('ts'), 946684800, 4102444800)
            or not _number(payload.get('sc'), 0, 100) or type(payload.get('hr')) is not bool):
        result['status'] = 'invalid_report_metadata'
        return result
    result.update(status='decoded', signal_count=len(decoded), signals=decoded,
                  client_score=payload['sc'], client_is_high_risk=payload['hr'],
                  client_timestamp=payload['ts'])
    return result


def decoder_provenance(version, configurations):
    config = configurations.get(version) if version else None
    return {'decoder_version': DECODER_VERSION, 'field_mapping_version': version,
            'mapping_digest': hashlib.sha256(json.dumps(config, sort_keys=True,
                separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()}

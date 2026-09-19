"""Closed LLM view of SDK observations; free-form evidence stays local."""
import math

# Public signal vocabulary reviewed against the pinned seed detector sources.
# This is a publication list, not an assertion that these detectors ran correctly.
PUBLIC_SIGNAL_IDS = frozenset(('sensor_replay_detected', 'emulator_behavior',
    'app_team_identifier_mismatch', 'app_identifier_bundle_mismatch'))
STATUSES = frozenset(('decoded', 'unsupported_schema', 'unsupported_sdk_version',
    'metadata_mismatch', 'missing_signals', 'invalid_signals', 'invalid_signal_state',
    'invalid_report_metadata', 'legacy_not_decoded'))


def project_detection(tokenizer, value):
    if not isinstance(value, dict):
        return {'status': 'legacy_not_decoded', 'trust': 'client_claim', 'signals': []}
    status = value.get('status')
    out = {'status': status if isinstance(status, str) and status in STATUSES else 'unknown',
           'trust': 'client_claim', 'signals': [], 'free_text_evidence_withheld': True}
    if value.get('decoder_version') == 'sdk-compact-1':
        out['decoder_version'] = 'sdk-compact-1'
    if value.get('sdk_version') == '7.3.0':
        out['sdk_version'] = '7.3.0'
    if status != 'decoded':
        return out
    for field in ('signal_count', 'client_score', 'client_timestamp'):
        number = value.get(field)
        if type(number) in (int, float) and math.isfinite(number):
            out[field] = number
    if type(value.get('client_is_high_risk')) is bool:
        out['client_is_high_risk'] = value['client_is_high_risk']
    signals = value.get('signals', [])
    for signal in signals[:20] if isinstance(signals, list) else []:
        if not isinstance(signal, dict) or not isinstance(signal.get('signal_id'), str):
            continue
        identifier = signal['signal_id']
        known = identifier in PUBLIC_SIGNAL_IDS
        item = {'signal_id': identifier if known else tokenizer._token('TEXT', identifier),
                'signal_id_known': known, 'state': {'type': 'unknown'}}
        score = signal.get('client_score')
        if type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 100:
            item['client_score'] = score
        state = signal.get('state')
        if isinstance(state, dict):
            kind = state.get('type')
            if kind in ('hard', 'soft', 'serverRequired', 'unavailable', 'tampered', 'unknown'):
                item['state']['type'] = kind
                if kind == 'hard' and type(state.get('detected')) is bool:
                    item['state']['detected'] = state['detected']
                if kind == 'soft' and type(state.get('confidence')) in (int, float) and 0 <= state['confidence'] <= 1:
                    item['state']['confidence'] = state['confidence']
        out['signals'].append(item)
    if type(value.get('signal_count')) is int:
        out['omitted_signal_count'] = max(0, value['signal_count'] - len(out['signals']))
    return out

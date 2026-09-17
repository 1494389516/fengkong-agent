"""Standalone release controller; deliberately never registered as an Agent tool.

Run with ``python -m agent.control_plane --store PATH --credentials PATH``;
stdin accepts one JSON request including a token. Credentials map SHA256(token)
to an authenticated principal and roles. Keep that file and release store outside
Agent mounts in deployment. The separate agent.release_publisher consumes activation events and emits signed
immutable bundles with an atomic active pointer. Production key provisioning is external.
"""
import argparse
import copy
import fcntl
import hashlib
import json
import math
import os
import tempfile
import uuid
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


class ReleaseController:
    GATES = {'Validated': ('Proposal', 'validator'),
             'Shadow': ('Validated', 'shadow_runner'),
             'Approved': ('Shadow', 'reviewer'),
             'Canary': ('Approved', 'release_controller'),
             'Active': ('Canary', 'release_controller')}
    REQUIRED = {'rules', 'model', 'features', 'sdk_contract', 'challenge', 'fallback',
                'code_digest', 'data_digest', 'canary_max_false_positive_delta'}

    def __init__(self, path, credentials, strict=False, scope=None):
        self.strict = strict
        self.scope = scope
        self.path = Path(path)
        self.credentials = copy.deepcopy(credentials)

    def _principal(self, token, role):
        identity = self.credentials.get(hashlib.sha256(token.encode()).hexdigest())
        if not identity or not identity.get('principal') or role not in identity.get('roles', []):
            raise PermissionError('authenticated %s role required' % role)
        if self.strict:
            expires = identity.get('expires_at')
            if type(expires) not in (float, int) or not math.isfinite(expires) or expires <= time.time():
                raise PermissionError('unexpired credential required')
            if not self.scope or self.scope not in identity.get('scopes', []):
                raise PermissionError('release scope denied')
        return identity['principal']

    @contextmanager
    def _transaction(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.with_suffix(self.path.suffix + '.lock').open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = (json.loads(self.path.read_text()) if self.path.exists()
                     else {'bundles': {}, 'active': None, 'activations': []})
            try:
                yield state
                payload = json.dumps(state, sort_keys=True, allow_nan=False)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix='.release-')
                try:
                    with os.fdopen(fd, 'w') as handle:
                        handle.write(payload)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(name, self.path)
                    directory = os.open(str(self.path.parent), os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                finally:
                    if os.path.exists(name):
                        os.unlink(name)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def snapshot(self):
        with self._transaction() as state:
            return copy.deepcopy(state)

    def propose(self, token, bundle):
        principal = self._principal(token, 'proposer')
        if not isinstance(bundle, dict) or not self.REQUIRED <= set(bundle):
            raise ValueError('complete immutable PolicyBundle required')
        if not isinstance(bundle['rules'], dict) or not bundle['rules']:
            raise ValueError('nonempty versioned rules mapping required')
        for component in ('model', 'features', 'sdk_contract', 'challenge', 'fallback',
                          'code_digest', 'data_digest'):
            if component == 'model' and isinstance(bundle[component], dict):
                continue
            if not isinstance(bundle[component], str) or not bundle[component].strip():
                raise ValueError('nonempty component identifier required: %s' % component)
        limit = bundle['canary_max_false_positive_delta']
        if type(limit) not in (int, float) or not math.isfinite(limit) or not 0 <= limit <= 1:
            raise ValueError('invalid canary error budget')
        if self.strict:
            for field in ('policy', 'strategy', 'model', 'feature', 'list', 'graph', 'versions'):
                if not isinstance(bundle.get(field), dict):
                    raise ValueError('runtime component mapping required: ' + field)
        bundle = copy.deepcopy(bundle)
        with self._transaction() as state:
            record = {'id': uuid.uuid4().hex, 'digest': digest(bundle), 'bundle': bundle,
                      'state': 'Proposal', 'proposed_by': principal,
                      'baseline_activation': state['active'], 'history': [], 'scope': self.scope, 'strict': self.strict}
            state['bundles'][record['id']] = record
            return copy.deepcopy(record)

    def transition(self, token, bundle_id, target, proof):
        if target not in self.GATES:
            raise ValueError('unknown release stage')
        previous, role = self.GATES[target]
        principal = self._principal(token, role)
        with self._transaction() as state:
            record = state['bundles'][bundle_id]
            if self.strict and record.get('scope') != self.scope:
                raise PermissionError('bundle belongs to another scope')
            if record['state'] != previous:
                raise ValueError('release gate cannot be skipped')
            if record['digest'] != digest(record['bundle']):
                raise ValueError('immutable bundle digest mismatch')
            if target == 'Approved' and principal == record['proposed_by']:
                raise PermissionError('proposer cannot approve own bundle')
            if proof.get('bundle_digest') != record['digest'] or proof.get('passed') is not True:
                raise ValueError('successful evidence bound to bundle digest required')
            if target in ('Approved', 'Canary', 'Active') and record['baseline_activation'] != state['active']:
                raise ValueError('baseline activation changed; propose and validate again')
            if self.strict:
                if proof.get('baseline_activation') != record['baseline_activation']:
                    raise ValueError('evidence baseline mismatch')
                evidence = proof.get('evidence')
                if not isinstance(evidence, dict) or not evidence or proof.get('evidence_digest') != digest(evidence):
                    raise ValueError('evidence digest binding required')
                expiry = evidence.get('expires_at')
                if evidence.get('scope') != self.scope or type(expiry) not in (float, int) or not math.isfinite(expiry) or expiry <= time.time():
                    raise ValueError('evidence scope or expiry invalid')
                if target in ('Shadow', 'Active') and (type(evidence.get('sample_count')) is not int or evidence['sample_count'] <= 0):
                    raise ValueError('nonempty observed sample required')
            if target == 'Active':
                delta = proof.get('false_positive_delta')
                if (type(delta) not in (int, float) or not math.isfinite(delta)
                        or not -1 <= delta <= 1
                        or delta > record['bundle']['canary_max_false_positive_delta']):
                    raise ValueError('canary false positive gate failed')
                self._activate(state, record, principal, 'activate', 'canary passed')
            record['state'] = target
            record['history'].append({'state': target, 'principal': principal,
                                      'proof': copy.deepcopy(proof), 'at': self._now()})
            if target == 'Active':
                state['activations'][-1]['history_digest'] = digest(record['history'])
            return copy.deepcopy(record)

    def rollback(self, token, bundle_id, reason):
        principal = self._principal(token, 'release_controller')
        if not reason or not reason.strip():
            raise ValueError('rollback reason required')
        with self._transaction() as state:
            record = state['bundles'][bundle_id]
            if self.strict and record.get('scope') != self.scope:
                raise PermissionError('bundle belongs to another scope')
            if record['state'] != 'Active' or record['digest'] != digest(record['bundle']):
                raise ValueError('rollback requires previously activated immutable bundle')
            return copy.deepcopy(self._activate(state, record, principal, 'rollback', reason))

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _activate(self, state, record, principal, kind, reason):
        event = {'id': uuid.uuid4().hex, 'bundle_id': record['id'],
                 'bundle_digest': record['digest'], 'previous': state['active'],
                 'principal': principal, 'kind': kind, 'reason': reason, 'at': self._now(),
                 'scope': record.get('scope'), 'history_digest': digest(record['history'])}
        state['activations'].append(event)
        state['active'] = event['id']
        return event


def main():
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', required=True)
    parser.add_argument('--credentials', required=True)
    parser.add_argument('--scope', required=True)
    args = parser.parse_args()
    controller = ReleaseController(args.store, json.loads(Path(args.credentials).read_text()), strict=True, scope=args.scope)
    request = json.load(sys.stdin)
    operation = request.pop('operation')
    if operation not in ('propose', 'transition', 'rollback'):
        raise ValueError('unknown operation')
    print(json.dumps(getattr(controller, operation)(**request), allow_nan=False))


if __name__ == '__main__':
    main()

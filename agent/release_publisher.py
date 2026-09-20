"""Separate release consumer. Private signing key belongs only to this process.

The runtime imports SignedBundleReader with a public key and read-only mount.
Journal and publisher directory must be writable only by release operators.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from .control_plane import digest


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def atomic(path, data):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.publish-')
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)


class SignedBundleReader:
    def __init__(self, root, public_key_path):
        self.root = Path(root)
        self.key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())

    def _verify(self, raw):
        try:
            doc = json.loads(raw)
            self.key.verify(base64.b64decode(doc['signature'], validate=True), canonical(doc['payload']))
            return doc['payload']
        except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
            raise ValueError('release signature invalid') from exc

    def read(self):
        pointer = self._verify((self.root / 'active.json').read_bytes())
        identifier = pointer['activation_id']
        if not isinstance(identifier, str) or len(identifier) != 32 or any(c not in '0123456789abcdef' for c in identifier):
            raise ValueError('invalid activation identifier')
        raw = (self.root / 'bundles' / (identifier + '.json')).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pointer['manifest_sha256']:
            raise ValueError('manifest digest mismatch')
        manifest = self._verify(raw)
        if manifest['activation']['id'] != identifier or digest(manifest['bundle']) != manifest['activation']['bundle_digest']:
            raise ValueError('bundle binding mismatch')
        for component in ('policy', 'strategy', 'model', 'feature', 'list', 'graph', 'versions'):
            if not isinstance(manifest['bundle'].get(component), dict):
                raise ValueError('invalid runtime component: ' + component)
        if not isinstance(manifest['bundle']['list'].get('records'), list):
            raise ValueError('explicit list records snapshot required')
        from .compute_admission import admit_bundle
        if manifest.get('compute_admission') != admit_bundle(manifest['bundle']):
            raise ValueError('runtime compute admission mismatch')
        return manifest

    def read_activation(self, activation_id):
        if not isinstance(activation_id, str) or len(activation_id) != 32 or any(c not in '0123456789abcdef' for c in activation_id):
            raise ValueError('invalid activation identifier')
        manifest = self._verify((self.root / 'bundles' / (activation_id + '.json')).read_bytes())
        if manifest['activation']['id'] != activation_id or digest(manifest['bundle']) != manifest['activation']['bundle_digest']:
            raise ValueError('bundle binding mismatch')
        for component in ('policy', 'strategy', 'model', 'feature', 'list', 'graph', 'versions'):
            if not isinstance(manifest['bundle'].get(component), dict):
                raise ValueError('invalid runtime component: ' + component)
        if not isinstance(manifest['bundle']['list'].get('records'), list):
            raise ValueError('explicit list records snapshot required')
        from .compute_admission import admit_bundle
        if manifest.get('compute_admission') != admit_bundle(manifest['bundle']):
            raise ValueError('runtime compute admission mismatch')
        return manifest


def publish(store, output, private_key):
    root = Path(output); (root / 'bundles').mkdir(parents=True, exist_ok=True)
    key = serialization.load_pem_private_key(Path(private_key).read_bytes(), password=None)
    def signed(payload):
        return canonical({'payload': payload, 'signature': base64.b64encode(key.sign(canonical(payload))).decode()})
    with (root / '.publish.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(Path(store).read_text())
        previous = None
        for event in state['activations']:
            if event['previous'] != previous: raise ValueError('activation chain broken')
            previous = event['id']
            record = state['bundles'][event['bundle_id']]
            if event['bundle_digest'] != digest(record['bundle']) or record['digest'] != event['bundle_digest']:
                raise ValueError('bundle changed after approval')
            for component in ('policy', 'strategy', 'model', 'feature', 'list', 'graph', 'versions'):
                if not isinstance(record['bundle'].get(component), dict):
                    raise ValueError('publish requires runtime mapping: ' + component)
            if not isinstance(record['bundle']['list'].get('records'), list):
                raise ValueError('explicit list records snapshot required')
            from .compute_admission import verify_record, verify_performance
            admission = verify_record(record, require_current_implementation=event['id'] == state['active'])
            history = record['history']
            if event.get('history_digest') != digest(history):
                raise ValueError('approval history changed after activation')
            if [h['state'] for h in history] != ['Validated','Shadow','Approved','Canary','Active']:
                raise ValueError('release gate history incomplete')
            for h in history:
                if h['state'] in ('Validated', 'Shadow', 'Active'):
                    verify_performance(h['proof'], admission, record['compute_capacity'])
                if h['proof'].get('bundle_digest') != record['digest'] or h['proof'].get('passed') is not True:
                    raise ValueError('evidence binding failed')
                if record.get('strict'):
                    proof = h['proof']; evidence = proof.get('evidence')
                    if not isinstance(evidence, dict) or proof.get('evidence_digest') != digest(evidence):
                        raise ValueError('evidence changed after review')
                    expiry = evidence.get('expires_at')
                    if evidence.get('scope') != record.get('scope') or type(expiry) not in (float,int) or expiry <= datetime.fromisoformat(h['at']).timestamp():
                        raise ValueError('evidence scope or time mismatch')
                    if proof.get('baseline_activation') != record['baseline_activation']:
                        raise ValueError('evidence baseline mismatch')
                if h['state'] == 'Approved' and h['principal'] == record['proposed_by']:
                    raise ValueError('self approval forbidden')
            delta = history[-1]['proof'].get('false_positive_delta')
            if type(delta) not in (float,int) or not -1 <= delta <= record['bundle']['canary_max_false_positive_delta']:
                raise ValueError('canary gate failed')
            manifest = {'version': 1, 'activation':event, 'bundle':record['bundle'], 'history_digest':digest(history), 'compute_admission': admission}
            payload = signed(manifest); path=root/'bundles'/(event['id']+'.json')
            if path.exists():
                if path.read_bytes() != payload: raise ValueError('immutable activation changed')
            else: atomic(path,payload)
            if event['id'] == state['active']:
                pointer = signed({'activation_id':event['id'],'manifest_sha256':hashlib.sha256(payload).hexdigest()})
        if previous != state['active']: raise ValueError('active pointer not latest activation')
        if previous is not None: atomic(root/'active.json',pointer)
    return previous


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--store',required=True);p.add_argument('--output',required=True);p.add_argument('--private-key',required=True)
    args=p.parse_args();print(json.dumps({'activation_id':publish(args.store,args.output,args.private_key)}))
if __name__ == '__main__':main()

"""Request-scoped verified release snapshots; publisher is the sole activation authority."""
import contextvars
import copy
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path

_state = contextvars.ContextVar('runtime_bundle', default=None)

def current_bundle():
    state = _state.get()
    return copy.deepcopy(state[0]['bundle']) if state and state[0] else None

def _check_scope(manifest):
    from .tenancy import current_context
    context = current_context()
    expected = ("tenant:%s/app:%s" % (context.tenant, context.app)
                if context is not None else os.environ.get("FK_RUNTIME_SCOPE"))
    if expected is not None and manifest["activation"].get("scope") != expected:
        raise PermissionError("runtime bundle tenant/app scope mismatch")

def _load():
    from .tenancy import current_context
    context = current_context()
    attributes = context.attributes if context is not None else {}
    root = attributes.get('runtime_bundle_dir') or os.environ.get('FK_RUNTIME_BUNDLE_DIR')
    if not root:
        return None, None
    from .release_publisher import SignedBundleReader
    from .tools.datasource import data_dir, atomic_write_json
    reader = SignedBundleReader(root, attributes.get('runtime_public_key') or os.environ['FK_RUNTIME_PUBLIC_KEY'])
    namespace = str(Path(root).resolve()) + ((':tenant:' + context.tenant + '/app:' + context.app) if context else ':unscoped')
    cache_root = Path(os.environ['FK_RUNTIME_CACHE_DIR']) if os.environ.get('FK_RUNTIME_CACHE_DIR') else data_dir()
    cache = cache_root / ('runtime_lkg_' + hashlib.sha256(namespace.encode()).hexdigest() + '.json')
    try:
        manifest = reader.read()
        _check_scope(manifest)
        atomic_write_json(cache, {'activation_id': manifest['activation']['id']})
        return manifest, None
    except Exception as exc:
        error = {'status':'invalid', 'required':True, 'reason':'runtime_bundle_invalid',
                 'error_type':type(exc).__name__, 'using_last_known_good':False}
        try:
            manifest = reader.read_activation(json.loads(cache.read_text())['activation_id'])
            _check_scope(manifest)
            error['using_last_known_good'] = True
            return manifest, error
        except Exception:
            raise RuntimeError('runtime_bundle_invalid:no_verified_last_known_good') from exc

@contextmanager
def request_bundle():
    if _state.get() is not None:
        yield
        return
    token = _state.set(_load())
    try:
        yield
    finally:
        _state.reset(token)

def annotate_bundle(result):
    state = _state.get()
    if state and state[0]:
        manifest, error = state
        result['runtime_activation_id'] = manifest['activation']['id']
        result['runtime_bundle_versions'] = copy.deepcopy(manifest['bundle'].get('versions', {}))
        if error:
            result.setdefault('components', {})['runtime_bundle'] = copy.deepcopy(error)
            result['degraded'] = True
            result.setdefault('degraded_reason', 'runtime_bundle_invalid')
    return result

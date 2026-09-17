"""Authenticated tenant/app routing. Configuration is server-owned, never input."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import time


@dataclass(frozen=True)
class AuthContext:
    principal: str
    tenant: str
    app: str
    dataset: str
    source_kind: str
    permissions: tuple
    expires_at: float
    attributes: dict = field(default_factory=dict, repr=False, compare=False)

    def require(self, permission):
        if self.expires_at <= time.time() or permission not in self.permissions:
            raise PermissionError('credential expired or permission denied')


_current = ContextVar('authenticated_data_context', default=None)


def current_context():
    return _current.get()


def registry():
    path = os.environ.get('FK_AUTH_CONFIG')
    if not path:
        return {}
    obj = json.loads(Path(path).read_text())
    if not isinstance(obj, dict):
        raise ValueError('invalid auth registry')
    domains = {}
    for key, row in obj.items():
        if not isinstance(key,str) or len(key)!=64 or not isinstance(row,dict):
            raise ValueError('invalid credential record')
        for name in ('principal','tenant','app','data_dir','source_kind'):
            if not isinstance(row.get(name),str) or not row[name].strip():
                raise ValueError('invalid credential field: '+name)
        expires=row.get('expires_at')
        if type(expires) not in (int,float) or not math.isfinite(expires):
            raise ValueError('credential must have finite expiry')
        if not isinstance(row.get('permissions'),list) or not all(isinstance(p,str) for p in row['permissions']):
            raise ValueError('credential permissions required')
        path = Path(row['data_dir'])
        if not path.is_absolute():
            raise ValueError('registered dataset must be absolute')
        canonical=str(path.resolve())
        domain=(row['tenant'],row['app'])
        if canonical in domains and domains[canonical]!=domain:
            raise ValueError('tenant/app domains cannot share one dataset')
        domains[canonical]=domain
    return obj


def authenticate(header):
    if not isinstance(header,str) or not header.startswith('Bearer '):
        raise PermissionError('bearer credential required')
    token=header[7:]
    row=registry().get(hashlib.sha256(token.encode()).hexdigest())
    if row is None:
        raise PermissionError('unknown credential')
    if row['expires_at']<=time.time():
        raise PermissionError('credential expired')
    return AuthContext(row['principal'],row['tenant'],row['app'],str(Path(row['data_dir']).resolve()),
                       row['source_kind'],tuple(row['permissions']),row['expires_at'],dict(row))


def authorized_dataset(tenant, dataset):
    canonical=str(Path(dataset).resolve())
    return any(r['tenant']==tenant and str(Path(r['data_dir']).resolve())==canonical
               and r['expires_at']>time.time() for r in registry().values())


@contextmanager
def data_context(context):
    if not isinstance(context,AuthContext) or context.expires_at<=time.time():
        raise PermissionError('valid authenticated context required')
    if not authorized_dataset(context.tenant,context.dataset):
        raise PermissionError('unregistered dataset')
    token=_current.set(context)
    try:
        yield context
    finally:
        _current.reset(token)

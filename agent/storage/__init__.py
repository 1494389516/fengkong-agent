"""Persistence primitives shared by the PostgreSQL and local SQLite adapters.

Business code owns transactions. PostgreSQL schemas are provisioned offline;
runtime credentials never need CREATE, ALTER, ownership, or superuser privileges.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

KINDS = ('online', 'agent', 'graph', 'features', 'knowledge')
SCHEMA_VERSION = 1
_projection_fence = ContextVar('graph_projection_fence', default=None)


def backend():
    value = os.environ.get('FK_STORAGE_BACKEND', 'sqlite')
    if value not in ('sqlite', 'postgres'):
        raise ValueError('FK_STORAGE_BACKEND must be sqlite or postgres')
    return value


def postgres(db=None):
    return getattr(db, 'dialect', None) == 'postgres' if db is not None else backend() == 'postgres'


def namespace():
    from ..tenancy import current_context, registry
    from ..tools.datasource import data_dir
    ctx = current_context()
    if ctx:
        identity = (ctx.tenant, ctx.app)
    else:
        root = data_dir()
        domains = {(r['tenant'], r['app']) for r in registry().values()
                   if Path(r['data_dir']).resolve() == root}
        if len(domains) == 1:
            identity = next(iter(domains))
        elif os.environ.get('FK_ENV') == 'production':
            raise PermissionError('PostgreSQL workers require one registered tenant/app dataset')
        else:
            identity = ('local', str(root))
    return 'fk_' + hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()[:32]


def schema(kind, prefix=None):
    if kind not in KINDS:
        raise ValueError('unknown storage kind')
    prefix = namespace() if prefix is None else prefix
    if not re.fullmatch(r'fk_[a-f0-9]{32}', prefix):
        raise ValueError('invalid storage namespace')
    return prefix + '_' + kind


def database_url():
    path = os.environ.get('FK_DATABASE_URL_FILE')
    value = Path(path).read_text().strip() if path else os.environ.get('FK_DATABASE_URL')
    if not value:
        raise ValueError('PostgreSQL database URL must be provisioned')
    return value


def lock_key(value):
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], 'big', signed=True)


def _parameters(sql):
    """Convert only unquoted qmark parameters, preserving SQL string literals.

    SQL is always application-owned; this does not translate SQL dialects or
    interpolate values. Literal percent signs must be escaped for psycopg.
    """
    tokens = re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")", sql)
    return ''.join(t.replace('%', '%%').replace('?', '%s') if i % 2 == 0
                   else t.replace('%', '%%') for i, t in enumerate(tokens))


class PostgresConnection:
    dialect = 'postgres'

    def __init__(self, kind, *, readonly=False, prefix=None, url=None, verify=True):
        import psycopg
        from psycopg import sql
        self.kind, self.readonly = kind, readonly
        self.prefix = namespace() if prefix is None else prefix
        self.schema = schema(kind, self.prefix)
        self._url = database_url() if url is None else url
        self.raw = psycopg.connect(self._url, autocommit=True, connect_timeout=10)
        try:
            self.raw.execute(sql.SQL('SET search_path TO {}, pg_catalog').format(sql.Identifier(self.schema)))
            self.raw.execute("SET lock_timeout = '10s'")
            self.raw.execute("SET statement_timeout = '30s'")
            if readonly:
                self.raw.execute('SET default_transaction_read_only = on')
            if verify:
                row = self.raw.execute('SELECT version FROM storage_version WHERE singleton=1').fetchone()
                if row != (SCHEMA_VERSION,):
                    raise RuntimeError('PostgreSQL schema migration required')
        except BaseException:
            self.raw.close()
            raise

    def execute(self, query, params=()):
        # Match SQLite's explicit-transaction DML contract, without implicit
        # read transactions that could keep stale snapshots or locks alive.
        verb = query.lstrip().split(None, 1)[0].upper()
        if verb in ('INSERT', 'UPDATE', 'DELETE') and not self.in_transaction:
            self.raw.execute('BEGIN')
        return self.raw.execute(_parameters(query), tuple(params)) if params else self.raw.execute(query)

    def executemany(self, query, values):
        if not self.in_transaction:
            self.raw.execute('BEGIN')
        cursor = self.raw.cursor()
        cursor.executemany(_parameters(query), values)
        return cursor

    @property
    def in_transaction(self):
        from psycopg.pq import TransactionStatus
        return self.raw.info.transaction_status != TransactionStatus.IDLE

    def commit(self):
        if self.in_transaction:
            self.raw.execute('COMMIT')

    def rollback(self):
        if self.in_transaction:
            self.raw.execute('ROLLBACK')

    def close(self):
        self.raw.close()

    def reconnect(self):
        return PostgresConnection(self.kind, readonly=self.readonly, prefix=self.prefix, url=self._url)


def connect(kind, *, readonly=False):
    return PostgresConnection(kind, readonly=readonly)


def begin_write(db, *, serialized=True):
    if not postgres(db):
        db.execute('BEGIN IMMEDIATE')
        return
    if db.in_transaction:
        raise RuntimeError('write transaction already active')
    db.execute('BEGIN')
    if serialized:
        # Preserve read/check/write invariants across machines. Long-running
        # Agent/LLM work is outside this lock. Queue claims use row locks instead.
        db.execute('SELECT pg_advisory_xact_lock(?)', (lock_key(db.schema + ':write'),))


def local_schema(db, script):
    """Legacy SQLite setup only. PostgreSQL runtime checks offline migrations."""
    if not postgres(db):
        db.executescript(script)


def table_names(db):
    if postgres(db):
        return {r[0] for r in db.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=?', (db.schema,))}
    return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def json_text(db, column, key):
    if not re.fullmatch(r'[a-z_]+', column) or not re.fullmatch(r'[a-z_]+', key):
        raise ValueError('invalid JSON expression')
    return f"({column}::jsonb ->> '{key}')" if postgres(db) else f"json_extract({column}, '$.{key}')"


def order_column(db, alias=''):
    return (alias + '.' if alias else '') + ('insertion_order' if postgres(db) else 'rowid')


def online_available():
    from ..tools.datasource import data_dir
    return postgres() or (data_dir() / 'online.sqlite3').exists()


def online_reader():
    from ..tools.datasource import data_dir
    return connect('online', readonly=True) if postgres() else sqlite3.connect(
        (data_dir() / 'online.sqlite3').as_uri() + '?mode=ro', uri=True)


@contextmanager
def projection_lock():
    from ..tools.datasource import data_dir, file_lock
    if not postgres():
        with file_lock(data_dir() / '.graph_projection'):
            yield
        return
    db = connect('graph')
    token = None
    try:
        # Session lock spans independent graph/feature transactions and releases
        # automatically after a process/connection failure.
        db.execute('SELECT pg_advisory_lock(?)', (lock_key(db.schema + ':projection'),))
        epoch = db.execute('UPDATE projection_epoch SET epoch=epoch+1 WHERE singleton=1 RETURNING epoch').fetchone()[0]
        db.commit()
        token = _projection_fence.set((db.prefix, epoch))
        yield
    finally:
        if token is not None:
            _projection_fence.reset(token)
        db.close()


def guard_projection(db):
    """Fence publication and queue deletion after loss of the lock connection.

    Lock the epoch row until the caller commits: a replacement owner cannot
    advance the epoch halfway through this publication transaction.
    """
    fence = _projection_fence.get()
    if postgres(db) and fence is not None:
        prefix, expected = fence
        if prefix != db.prefix:
            raise PermissionError('projection namespace changed')
        row = db.execute('SELECT epoch FROM '+schema('graph', prefix)+
                         '.projection_epoch WHERE singleton=1 FOR UPDATE').fetchone()
        if row != (expected,):
            raise RuntimeError('graph projection fencing epoch replaced')

"""Small-corpus, dataset-local SQLite index with atomic full-corpus replacement.

BM25 is always available. Real embeddings are optional and explicitly configured;
there is no hash-vector substitute masquerading as semantic retrieval.
"""
import hashlib
import json
import math
import re
import sqlite3
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

MAX_DOCUMENTS = 1000
MAX_CHUNKS = 10000
MAX_CHUNK_CHARS = 600


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('timestamp must be an ISO-8601 string with timezone')
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    return dt.timestamp()


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+\.\d+\.\d+', value):
        raise ValueError('SDK version must be major.minor.patch')
    return tuple(map(int, value.split('.')))


def tokens(text):
    """Keep exact identifiers; CJK unigrams/bigrams support Chinese offline."""
    result = re.findall(r'[a-z0-9_]+', text.lower())
    for part in re.findall(r'[\u4e00-\u9fff]+', text):
        result.extend(part)
        result.extend(part[i:i + 2] for i in range(len(part) - 1))
    return result


def read_documents(directory):
    files = sorted(Path(directory).rglob('*.json'))
    if not files or len(files) > MAX_DOCUMENTS:
        raise ValueError('corpus must contain 1..1000 JSON documents')
    chunks, seen = [], set()
    for path in files:
        if path.stat().st_size > 200000:
            raise ValueError('document exceeds 200 KB: ' + str(path))
        doc = json.loads(path.read_text(encoding='utf-8'))
        for key in ('knowledge_id', 'title', 'type', 'status', 'platform', 'source',
                    'known_at', 'reviewed_at', 'review_basis', 'caveats', 'applicability'):
            if not isinstance(doc.get(key), str) or not doc[key].strip():
                raise ValueError('missing document field: ' + key)
        ident = doc['knowledge_id']
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}', ident) or ident in seen:
            raise ValueError('invalid or duplicate knowledge_id')
        seen.add(ident)
        if doc['type'] not in ('detector_doc', 'attack_case', 'false_positive_case', 'playbook'):
            raise ValueError('invalid document type')
        if doc['type'] in ('attack_case', 'false_positive_case') and not (isinstance(doc.get('case_id'), str) and doc['case_id'].strip()):
            raise ValueError('case documents require their originating case_id')
        if doc['status'] not in ('draft', 'reviewed', 'withdrawn'):
            raise ValueError('invalid review status')
        if doc['platform'] not in ('ios', 'android', 'all'):
            raise ValueError('invalid platform')
        if any(len(doc[key]) > 600 for key in ('title', 'source', 'caveats', 'applicability', 'review_basis')):
            raise ValueError('metadata exceeds projection budget')
        timestamp(doc['known_at']); timestamp(doc['reviewed_at'])
        if doc.get('export_policy') not in ('public_reference', 'local_only'):
            raise ValueError('explicit export_policy required')
        if type(doc.get('simulated')) is not bool:
            raise ValueError('simulated must be an explicit boolean')
        ids = doc.get('detector_ids')
        if not isinstance(ids, list) or len(ids) > 30 or any(not isinstance(x, str) or not x or len(x) > 100 for x in ids):
            raise ValueError('invalid detector_ids')
        for key in ('sdk_version_min', 'sdk_version_max'):
            if doc.get(key) is not None:
                version(doc[key])
        if doc.get('sdk_version_min') and doc.get('sdk_version_max') and version(doc['sdk_version_min']) > version(doc['sdk_version_max']):
            raise ValueError('inverted SDK version range')
        sections = doc.get('sections')
        if not isinstance(sections, list) or not sections:
            raise ValueError('sections required')
        doc_hash = digest(doc)
        for index, section in enumerate(sections):
            if not isinstance(section, dict) or set(section) != {'heading', 'text'}:
                raise ValueError('section requires heading and text')
            if any(not isinstance(v, str) or not v.strip() for v in section.values()):
                raise ValueError('empty section')
            if len(section['text']) > MAX_CHUNK_CHARS or len(section['heading']) > 100:
                raise ValueError('split long sections semantically before ingesting')
            # Caveats travel with EVERY hit, even if a section is retrieved alone.
            row = {k: v for k, v in doc.items() if k != 'sections'}
            row.update(section=section['heading'], text=section['text'],
                       content_hash=doc_hash, chunk_id=f'{ident}-{doc_hash[:16]}-{index}')
            chunks.append(row)
    if len(chunks) > MAX_CHUNKS:
        raise ValueError('small-corpus chunk budget exceeded')
    return chunks


def index_path():
    from agent.tools.datasource import data_dir
    return data_dir() / 'risk_knowledge.sqlite3'


def index_metadata():
    """Read only the generation at task creation, without loading corpus text."""
    path = index_path()
    if not path.exists():
        return {}
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        return dict(db.execute('SELECT key,value FROM metadata'))


def read_index():
    path = index_path()
    if not path.exists():
        return {}, []
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        # One read transaction keeps metadata and chunks from the same generation.
        db.execute('BEGIN')
        meta = dict(db.execute('SELECT key,value FROM metadata'))
        rows = [json.loads(r[0]) for r in db.execute('SELECT body FROM chunks ORDER BY chunk_id LIMIT ?', (MAX_CHUNKS + 1,))]
    if len(rows) > MAX_CHUNKS:
        raise ValueError('index exceeds small-corpus budget')
    return meta, rows


def ingest(directory, embedder=None):
    chunks = read_documents(directory)
    path = index_path()
    from agent.tools.datasource import file_lock
    with file_lock(path):
        old_meta, old_rows = read_index()
        model = embedder.identity if embedder else ''
        old = {r['chunk_id']: r for r in old_rows} if old_meta.get('embedding_model') == model else {}
        fresh = []
        for row in chunks:
            if embedder:
                cached = old.get(row['chunk_id'], {}).get('embedding')
                if cached is not None:
                    row['embedding'] = cached
                else:
                    fresh.append(row)
        if embedder and any(r['export_policy'] != 'public_reference' for r in chunks):
            raise ValueError('embedding endpoint only accepts public_reference corpus')
        if fresh:
            vectors = embedder.embed([embedding_text(r) for r in fresh])
            validate_vectors(vectors, len(fresh))
            for row, vector in zip(fresh, vectors):
                row['embedding'] = vector
        if embedder:
            validate_vectors([r['embedding'] for r in chunks], len(chunks))
        generation = digest({'chunks': chunks, 'embedding_model': model})
        meta = {'index_digest': generation, 'embedding_model': model,
                'indexed_at': datetime.now(timezone.utc).isoformat()}
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS chunks(chunk_id TEXT PRIMARY KEY,body TEXT NOT NULL)')
            db.execute('DELETE FROM chunks')
            db.execute('DELETE FROM metadata')
            db.executemany('INSERT INTO chunks VALUES(?,?)', [(r['chunk_id'], canonical(r)) for r in chunks])
            db.executemany('INSERT INTO metadata VALUES(?,?)', list(meta.items()))
    return {'chunks': len(chunks), 'index_digest': generation, 'embedded_new': len(fresh),
            'mode': 'hybrid' if embedder else 'bm25'}


def embedding_text(row):
    return '\n'.join([row['title'], ' '.join(row['detector_ids']), row['section'],
                      row['text'], row['caveats'], row['applicability']])


def validate_vectors(vectors, count):
    if not isinstance(vectors, list) or len(vectors) != count:
        raise ValueError('embedding count mismatch')
    dimension = None
    for vector in vectors:
        if not isinstance(vector, list) or not vector or len(vector) > 16384:
            raise ValueError('invalid embedding shape')
        if any(type(x) not in (int, float) or not math.isfinite(x) for x in vector):
            raise ValueError('embedding contains nonfinite values')
        norm = math.hypot(*vector)
        if not math.isfinite(norm) or norm == 0:
            raise ValueError('invalid embedding norm')
        dimension = dimension or len(vector)
        if len(vector) != dimension:
            raise ValueError('embedding dimensions differ')


def bm25(query, rows):
    counters = [Counter(tokens(embedding_text(r))) for r in rows]
    lengths = [sum(c.values()) for c in counters]
    average = sum(lengths) / max(1, len(rows)) or 1
    terms = set(tokens(query))
    freq = {t: sum(t in c for c in counters) for t in terms}
    scores = []
    for index, counter in enumerate(counters):
        score = 0.0
        for term in terms:
            tf = counter[term]
            idf = math.log(1 + (len(rows) - freq[term] + .5) / (freq[term] + .5))
            if tf:
                score += idf * tf * 2.5 / (tf + 1.5 * (.25 + .75 * lengths[index] / average))
        if score > 0:
            scores.append((index, score))
    return sorted(scores, key=lambda x: (-x[1], rows[x[0]]['chunk_id']))


def search(query, *, platform='', detector_ids=None, sdk_version='', as_of='', top_k=5,
           exclude_case_id='', expected_digest=None, embedder=None, public_only=False):
    if not isinstance(query, str) or not query.strip() or len(query) > 2000:
        raise ValueError('query must contain 1..2000 characters')
    if type(top_k) is not int or not 1 <= top_k <= 10:
        raise ValueError('top_k must be 1..10')
    if platform not in ('', 'ios', 'android'):
        raise ValueError('unsupported platform')
    if detector_ids is not None and (not isinstance(detector_ids, list) or len(detector_ids) > 30 or any(not isinstance(x, str) or len(x) > 100 for x in detector_ids)):
        raise ValueError('invalid detector_ids')
    requested_version = version(sdk_version) if sdk_version else None
    anchor = timestamp(as_of) if as_of else datetime.now(timezone.utc).timestamp()
    meta, rows = read_index()
    if expected_digest is not None and meta.get('index_digest', '') != expected_digest:
        raise ValueError('knowledge index changed; reissue investigation with a new snapshot')
    eligible = []
    for row in rows:
        if public_only and row.get('export_policy') != 'public_reference':
            continue
        if row['status'] != 'reviewed' or row['simulated']:
            continue
        if max(timestamp(row['known_at']), timestamp(row['reviewed_at'])) > anchor:
            continue
        if exclude_case_id and row.get('case_id') == exclude_case_id:
            continue
        if platform and row['platform'] not in (platform, 'all'):
            continue
        if detector_ids and not set(detector_ids).intersection(row['detector_ids']):
            continue
        lo, hi = row.get('sdk_version_min'), row.get('sdk_version_max')
        if (lo or hi) and requested_version is None:
            continue  # Never silently assume the caller's SDK version.
        if requested_version and ((lo and requested_version < version(lo)) or (hi and requested_version > version(hi))):
            continue
        eligible.append(row)
    ranked = bm25(query, eligible)
    modes = ['bm25']
    warning = ''
    fused = {i: 1 / (60 + rank) for rank, (i, _) in enumerate(ranked[:50], 1)}
    if embedder and eligible and meta.get('embedding_model') == embedder.identity:
        try:
            vectors = embedder.embed([query])
            validate_vectors(vectors, 1)
            q = vectors[0]; qnorm = math.hypot(*q)
            semantic = []
            for i, row in enumerate(eligible):
                v = row.get('embedding')
                validate_vectors([v], 1)
                if len(v) != len(q):
                    raise ValueError('query/index embedding dimensions differ')
                vnorm = math.hypot(*v)
                score = sum((a / qnorm) * (b / vnorm) for a, b in zip(q, v))
                if score > 0:
                    semantic.append((i, score))
            semantic.sort(key=lambda x: (-x[1], eligible[x[0]]['chunk_id']))
            for rank, (i, _) in enumerate(semantic[:50], 1):
                fused[i] = fused.get(i, 0) + 1 / (60 + rank)
            modes.append('vector')
        except Exception:
            warning = 'embedding unavailable or invalid; lexical retrieval only'
    elif embedder:
        warning = 'embedding model/index mismatch or empty corpus; lexical retrieval only'
    hits = []
    for i in sorted(fused, key=lambda i: (-fused[i], eligible[i]['chunk_id']))[:top_k]:
        row = {k: v for k, v in eligible[i].items() if k != 'embedding'}
        row.update(citation='[K:' + row['chunk_id'] + ']', relevance=round(fused[i], 6))
        hits.append(row)
    return {'status': 'ok' if hits else 'no_match', 'hits': hits, 'mode': '+'.join(modes),
            'index_digest': meta.get('index_digest', ''), 'as_of': as_of or datetime.fromtimestamp(anchor, timezone.utc).isoformat(),
            'warning': warning, 'interpretation': 'Reference knowledge only; relevance is not fraud probability.'}

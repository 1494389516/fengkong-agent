"""Explicit opt-in to an operator-owned OpenAI-compatible embedding endpoint."""
import os


class EndpointEmbedder:
    def __init__(self):
        from openai import OpenAI
        endpoint = os.environ['FK_RAG_EMBED_BASE_URL']
        model = os.environ['FK_RAG_EMBED_MODEL']
        if not endpoint.startswith(('https://', 'http://localhost:', 'http://127.0.0.1:')):
            raise ValueError('embedding endpoint requires HTTPS or loopback')
        if not model.strip():
            raise ValueError('embedding model is required')
        self.model = model
        self.identity = endpoint.rstrip('/') + '|' + model
        self.client = OpenAI(base_url=endpoint, api_key=os.environ['FK_RAG_EMBED_API_KEY'],
                             timeout=15.0, max_retries=0)

    def embed(self, texts):
        vectors = []
        for offset in range(0, len(texts), 32):
            batch = texts[offset:offset + 32]
            def invoke():
                result = self.client.embeddings.create(model=self.model, input=batch)
                data = sorted(result.data, key=lambda d: d.index)
                if [r.index for r in data] != list(range(len(batch))):
                    raise ValueError('embedding response indexes mismatch')
                usage = getattr(result, 'usage', None)
                actual = getattr(usage, 'total_tokens', None)
                if type(actual) is not int or actual < 0: actual = None
                return [list(row.embedding) for row in data], actual
            from agent.run_ledger import metered_call
            vectors.extend(metered_call('embedding', {'model':self.identity,'texts':batch},
                sum(len(text.encode()) for text in batch)+128*len(batch), invoke))
        return vectors


def configured_embedder():
    if os.environ.get('FK_RAG_EMBED_ENABLED') != '1':
        return None
    return EndpointEmbedder()

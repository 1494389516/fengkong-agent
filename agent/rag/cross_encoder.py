"""Optional local CrossEncoder reranker.

No model is downloaded unless the operator explicitly opts in. The default path
is offline/local-files-only so private queries and corpus text are not sent to a
remote inference service.
"""
import math
import os


class LocalCrossEncoderReranker:
    def __init__(self):
        model = os.environ.get("FK_RAG_RERANK_MODEL", "").strip()
        if not model:
            raise ValueError("FK_RAG_RERANK_MODEL is required")
        try:
            from sentence_transformers import CrossEncoder
        except ImportError as exc:
            raise RuntimeError(
                "sentence-transformers is required for local cross-encoder reranking"
            ) from exc
        allow_download = os.environ.get("FK_RAG_RERANK_ALLOW_DOWNLOAD") == "1"
        revision = os.environ.get("FK_RAG_RERANK_REVISION", "").strip()
        kwargs = {"trust_remote_code": False}
        if not allow_download:
            kwargs["local_files_only"] = True
        if revision:
            kwargs["revision"] = revision
        self.model_name = model
        self.revision = revision
        self.identity = "cross-encoder|" + model + ("@" + revision if revision else "")
        self.model = CrossEncoder(model, **kwargs)

    def score(self, query, passages):
        if not passages:
            return []
        pairs = [(query, passage) for passage in passages]
        values = self.model.predict(pairs, show_progress_bar=False)
        scores = [float(value) for value in values]
        if len(scores) != len(passages) or any(not math.isfinite(x) for x in scores):
            raise ValueError("invalid cross-encoder scores")
        return scores


def configured_reranker():
    if os.environ.get("FK_RAG_RERANK_ENABLED") != "1":
        return None
    return LocalCrossEncoderReranker()

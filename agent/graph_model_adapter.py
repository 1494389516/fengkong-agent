"""Graph model adapter contract.

No ML framework is required by the online service. GNN implementations must sit
behind this contract and remain shadow-only until normal model/release gates pass.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class GraphModelOutput:
    model_name: str
    model_version: str
    score: float
    features: dict
    explanation: dict


class GraphModelAdapter:
    model_name="abstract"
    model_version="0"

    def score(self,snapshot,target_device,target_generation):
        raise NotImplementedError


class StructuralFeatureAdapter(GraphModelAdapter):
    """Adapter for the current deterministic graph algorithm family."""
    def __init__(self,algorithm):
        self.algorithm=algorithm
        self.model_name="structural:"+algorithm.name
        self.model_version=algorithm.version

    def score(self,snapshot,target_device,target_generation):
        result=self.algorithm.compute(
            list(snapshot.rows),target_device,target_generation,
            truncated=snapshot.truncated)
        score=float(result.get("community_risk_density",0.0))
        return GraphModelOutput(
            self.model_name,self.model_version,score,result,
            {"kind":"structural_association","community_id":result.get("community_id"),
             "risk_tags":list(result.get("risk_tags",[])),
             "snapshot_fingerprint":snapshot.fingerprint})


class CallableGNNAdapter(GraphModelAdapter):
    """Offline/research seam for PyG/DGL/etc. The callable is injected by the trainer.

    This adapter is intentionally not constructible from arbitrary runtime config.
    """
    def __init__(self,name,version,predict):
        if not isinstance(name,str) or not name or not isinstance(version,str) or not version:
            raise ValueError("model identity required")
        if not callable(predict):
            raise ValueError("predict callable required")
        self.model_name=name;self.model_version=version;self._predict=predict

    def score(self,snapshot,target_device,target_generation):
        raw=self._predict(snapshot,target_device,target_generation)
        if not isinstance(raw,dict):
            raise ValueError("GNN predictor must return dict")
        score=float(raw.get("score"))
        if not 0.0<=score<=1.0:
            raise ValueError("GNN score must be in [0,1]")
        explanation=raw.get("explanation") or {}
        if not isinstance(explanation,dict):
            raise ValueError("GNN explanation must be dict")
        return GraphModelOutput(
            self.model_name,self.model_version,score,
            dict(raw.get("features") or {}),dict(explanation))

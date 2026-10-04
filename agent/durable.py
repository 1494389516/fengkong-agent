# -*- coding: utf-8 -*-
"""Small durable checkpoint store for long-running risk investigations.

The checkpoint is JSON-only by design: no pickle/deserialization of executable
Python objects. Production can replace this adapter without changing callers.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional

from .tools.datasource import agent_state_dir, file_lock

SCHEMA_VERSION = 1

@dataclass
class InvestigationCheckpoint:
    run_id: str
    case_id: str
    step: str
    state: Dict[str, Any]
    status: str = "running"
    waiting_for: Optional[str] = None
    schema_version: int = SCHEMA_VERSION
    updated_at: float = 0.0

    def __post_init__(self):
        if not self.updated_at:
            self.updated_at = time.time()


class CheckpointStore:
    def __init__(self, root: Optional[Path] = None):
        self.root = Path(root or (agent_state_dir() / "agent_checkpoints"))

    def _path(self, run_id: str) -> Path:
        if not run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in run_id):
            raise ValueError("invalid run_id")
        return self.root / (run_id + ".json")

    def save(self, checkpoint: InvestigationCheckpoint) -> Path:
        if checkpoint.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint schema")
        checkpoint.updated_at = time.time()
        path = self._path(checkpoint.run_id)
        payload = json.dumps(asdict(checkpoint), ensure_ascii=False, sort_keys=True, default=str)
        with file_lock(path):
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        return path

    def load(self, run_id: str) -> InvestigationCheckpoint:
        raw = json.loads(self._path(run_id).read_text(encoding="utf-8"))
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint schema")
        return InvestigationCheckpoint(**raw)

    def interrupt(self, run_id: str, case_id: str, step: str,
                  state: Dict[str, Any], waiting_for: str) -> InvestigationCheckpoint:
        cp = InvestigationCheckpoint(run_id, case_id, step, state,
                                     status="interrupted", waiting_for=waiting_for)
        self.save(cp)
        return cp

    def resume(self, run_id: str, resume_value: Any) -> InvestigationCheckpoint:
        cp = self.load(run_id)
        if cp.status != "interrupted":
            raise ValueError("checkpoint is not interrupted")
        cp.state = dict(cp.state)
        cp.state["resume_value"] = resume_value
        cp.status = "running"
        cp.waiting_for = None
        self.save(cp)
        return cp

# -*- coding: utf-8 -*-
"""Architecture invariants for the Agent governance boundary.

Run: python eval/governance_invariants.py
"""
import json
import tempfile
from pathlib import Path

from agent.durable import CheckpointStore, InvestigationCheckpoint
from agent import governance


def check(name, cond):
    if not cond:
        raise AssertionError(name)
    print("[OK]", name)


def main():
    governance.reset_trajectory("eval-run")
    d = governance.decide("account_profile", {"uid": "u1"}, True)
    check("read defaults allow after existing capability gate", d.outcome == "allow")

    # Simulate untrusted RAG provenance without executing a real data tool.
    state = governance._trajectory.get()
    state["trust"].append("external")
    d = governance.decide("model_register", {}, True)
    # Existing capability enforcement may deny earlier when no RequestScope is
    # present; either way execute must never be allowed.
    check("untrusted trajectory cannot allow execute", d.outcome == "deny")

    with tempfile.TemporaryDirectory() as td:
        store = CheckpointStore(Path(td))
        cp = InvestigationCheckpoint("run_1", "case_1", "evidence", {"n": 1})
        store.save(cp)
        loaded = store.load("run_1")
        check("checkpoint round-trip", loaded.state == {"n": 1})
        store.interrupt("run_1", "case_1", "approval", {"proposal": "p1"}, "human_approval")
        resumed = store.resume("run_1", {"approved": True})
        check("interrupt/resume", resumed.state["resume_value"]["approved"] is True)

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "audit.jsonl"
        # Verify synthetic chain using the same canonical hash contract.
        prev = ""
        rows = []
        for i in range(2):
            body = {"i": i, "previous_hash": prev}
            body["record_hash"] = governance._digest(body)
            prev = body["record_hash"]
            rows.append(body)
        p.write_text("\n".join(json.dumps(x, sort_keys=True) for x in rows) + "\n", encoding="utf-8")
        check("hash-chain verifier accepts intact log", governance.verify_audit_chain(p)["ok"])
        rows[0]["i"] = 99
        p.write_text("\n".join(json.dumps(x, sort_keys=True) for x in rows) + "\n", encoding="utf-8")
        check("hash-chain verifier detects tamper", not governance.verify_audit_chain(p)["ok"])

    print("governance invariants passed")


if __name__ == "__main__":
    main()

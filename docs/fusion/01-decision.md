# Decision adapter repair
Source SHA: 1548785eccd5500545e5850d7399ba4b64158c4c. Issues C07 C08 C09 C11 C12.

Preserve remote effective metadata separately from expected local versions; publish component degradation; reject nonnumeric/nonfinite/out-of-range scores; isolate online/batch endpoint circuit and bulkhead with generation-bound half-open leases; report invalid registries with per-path last-known-good state.

Red evidence: initial 11 assertions failed (plus missing-networkx import error); supplemental lease/metadata/snapshot tests reproduced 9 failures before repair. Final targeted command: python -m pytest tests/test_fusion_decision.py -q (13 passed, 21 subtests).

Limits: LKG and concurrency limits are process-local; no global atomic snapshot across all registries, no hard end-to-end HTTP deadline or cryptographic model-version proof. No Detector/threshold changes.

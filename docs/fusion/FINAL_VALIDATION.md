# Fusion implementation validation — 2026-09-17

Source commits were fixed before editing:
- Agent: `1548785eccd5500545e5850d7399ba4b64158c4c`
- SDK: `6aeaf6783247258eba3f516efebd006561d4471c`

Implementation uses five stacked Agent draft PRs and one independent SDK draft PR, with test commits preceding repair commits. No merge or production deployment was performed. Five domain agents implemented disjoint files, an independent verifier checked cross-module behavior, and the integrator assigned follow-up file ownership. Conflicts were decided from reproductions, not voting.

## Actual final results

| Command | Actual result | Scope |
|---|---|---|
| `python -m pytest tests -q` | 95 passed, 43 subtests passed, exit 0 | Agent tests directory; independently executed after final source freeze |
| `python eval/run_eval.py --offline` | 510 PASS, 0 FAIL, 0 EXCEPTION, exit 0 | Existing complete offline evaluation; LLM/API evaluation deliberately not called |
| `python -m unittest discover -s contracts/tests -v` in SDK | 8 passed, exit 0; includes 20 shared vectors | Python reference contracts |
| `git diff --check` in both repos | exit 0 | Whitespace/patch integrity |
| Swift test invocation | exit 127, `swift: command not found` | Not executed; no Xcode, Apple assertion or physical-device acceptance claim |

The implementation tests first reproduced failures. Per-domain evidence is in 01–05 markdown files and SDK `contracts/IMPLEMENTATION_EVIDENCE.md`. Initial full offline evaluation had 41 failures. Existing assertions were retained and migrated to explicit authorization, finite whitelist scope/expiry, pinned graph times, authoritative remote metadata, complete job output, and isolated real online event history. This process found actual optional-resource HTTP 500 and plotting numeric-dtype defects; both were repaired after failing regression tests. Final independent pytest also caught a test fixture copying runtime idempotency state; it now copies only the ten tracked static JSON seeds, without deleting real data or weakening migration protection.

## Review order

1. Agent #18: decision metadata, score, degradation and circuit.
2. Agent #19: event/decision/outbox transactions, missing-history closure, input validation.
3. Agent #20: request/task authorization, isolation and full results.
4. Agent #21: proposal evidence, baseline CAS, scoped whitelists and standalone release journal.
5. Final Agent integration PR: temporal graph, migrated offline regression, and independently discovered boundary repairs. This contains final fixes to state/task/feature code discovered after their initial draft PR snapshots.
6. SDK #83 is independent; native and collector acceptance must be completed before approval.

## Explicit incomplete acceptance gates

- C01/C02/C03/C05/C06/G05: Swift tests are present but unexecuted. Generated DTO parity, production Collector integration, complete floating-point canonicalization, server identity-resolution integration, real Apple assertion/HKDF/armor chain and device validation remain pending.
- C12/C24: registry LKG and threshold CAS are useful repairs, not one immutable atomic snapshot across every model/rule/feature/graph registry. Fixed forensic replay is not claimed.
- C18: process-local worker/bulkhead bounds and lease tests, not distributed quotas or real kill/power-loss certification.
- C21: graph has explicit output-schema allowlisting; other tool outputs still need per-tool schema review.
- G02: deployment-bound tenant/dataset and transactional row scopes are enforced, but dynamic multi-tenant routing of all intel/config/artifact stores is not implemented.
- G06: the standalone authenticated controller persists desired activation events. Runtime/deployer consumption, production-metric attestation, KMS and deployment credential/mount isolation are not verified. No production credentials were supplied to Agent.
- Legacy nonempty `decide_idemp.json` deliberately blocks activation until a reviewed migration/drain plan exists; no silent deduplication reset. Old unsafe white records fail closed and require migration.

The JSON issue register preserves all original audit entries and adds implementation/test status. `closed: false` intentionally prevents local passing tests from being mistaken for complete production acceptance. No existing Detector threshold was changed, no SDK→LLM path was added, and no native vulnerability-clearance claim is made.

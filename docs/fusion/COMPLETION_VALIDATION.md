# Fusion completion — 2026-09-17

## Frozen sources and integration

Original audit: Agent `1548785eccd5500545e5850d7399ba4b64158c4c`, SDK `6aeaf6783247258eba3f516efebd006561d4471c`.
Continuation source: Agent main `c4fcae46178e8b13e283029ddedaffb9e43d40d0`, SDK main `336cc689740c84a2d506d8b6dba50e3b484ad010`.
Previous Agent stacked packages ended at `7333318ed11d58ae4fd50632988d8bac8b26eb53`; merging their stacked PRs did not put all packages on main. This completion branch explicitly integrates that source; local frozen integration baseline `d034f021d7a24b906e68aee9af50a71c63ea0c09`.

## Executable changes and red-to-green evidence

| Issues | Trigger / minimal reproduction | Fix and tests |
|---|---|---|
| C01–C03 | Actual network dictionary omitted proof/context; exact float/Unicode signed bytes differ from Python recanonicalization | Generated Swift/Python DTO, exact-byte verifier, 20 legacy + 8 wire vectors; SDK `contracts/tests` and `FusionTransportTests`. Initial 2 failures + 1 missing API error. |
| C05/C06/G05 | Same hardware incorrectly used as identity; client claims server aggregate | Server tenant/app/domain/key-version HMAC installation + generation, separate hardware vector; authenticated Collector discards aggregation claims. `test_completion_ingress`, graph tests. |
| C07–C09/C11/C12/C15 | Remote actual version lost, missing model treated as complete, corrupt registry, unbounded half-open | Explicit producer/effective/expected metadata, component states, strict scores, bounded circuit probes, signed bundle/LKG revalidation. `test_fusion_decision`, `test_completion_runtime`, public DTO tests. |
| C13/C14/G01/G02/G04 | Crash mid-write, cross-tenant same ID, late event known too early | Atomic SQLite decision/event/outbox, original-request idempotency before enrichment, recorded_at supplied only by server, immutable history snapshots; actual process exit/restart and HTTP concurrent tenant tests. G04 independent test initially FAIL. |
| C16–C21 | Empty scope grants privilege, worker restart loses authorization, truncated artifact, novel nested PII | Explicit request/task scope, persistent bounded jobs/leases, worker SIGKILL recovery, independent full artifact, per-tool closed result schemas, opaque unknown strings, real tool/token/entity/time/graph budgets. `test_fusion_security`, `test_completion_security`, independent tests. |
| C22–C26/G06 | Reused proposal ID, evidence for different values, stale baseline, forged actor, timeless whitelist | Unique IDs, digest and baseline CAS, scoped expiring controller identity, separate signed publisher, runtime consumes pinned bundle, rollback is new activation. Real subprocess Controller→publisher→engine→rollback test. |
| C27/C28 | Shared IP produces malicious component; expired list disagrees between graph/rules | Weak IP edges, time/knowledge filters, installation generations, shared effective TTL list; SQL bounded graph load and next-request cache invalidation. Graph/datasource tests. |

Additional independent failures were fixed: public release metadata omissions; `/brief` lacked scoped permission; anonymous health leaked readiness; task prompt lacked evidence; task max_rounds was ineffective; new-tenant enrichment opened another SQLite writer; old successful requests failed replay after report freshness expired. Tests exercise real HTTP, databases and subprocesses; the LLM API is stubbed where invoked.

## Operation

- `/reports` requires SDK `reports.write`; `/decide` and typed `/decisions` require business `decisions.write`. Authenticated configuration supplies tenant/app, never request fields.
- App Attest enrollment validates against an operator-pinned Apple root, binds a one-time server challenge and persists the attestation evidence. Reports verify the payload assertion plus a fresh challenge assertion; counters/challenge/evidence commit together. Software-generated CA and P256 tests are **not** real Apple device validation. Unknown authenticator extensions fail closed.
- `python scripts/sync_fusion_contract.py --sdk /path/to/sdk --check` verifies six vendored contract files byte-for-byte.
- Legacy idempotency migration: stop old writers; run `FK_DATA_DIR=... python -m agent.tools.online_store migrate-legacy --tenant T --app A --mapping FILE`. Mapping binds every old key to its real original event and source kind. No event data is invented when unavailable.
- `deploy/` separates Collector, decision runtime, read-only investigator, controller and publisher. Agent receives no publisher private key, release approval credentials or writable release mount. Samples deliberately contain no usable credentials.

## Limits

SQLite and local durable workers target one host/shared local disk, not a distributed queue. Apple production enrollment, real LLM behavior, container permission enforcement on the deployment host, KMS custody and device/native safety require deployment-specific acceptance. Arbitrary prose is conservatively tokenized; fixed rule/reason codes and numeric evidence remain usable. No unrelated Detector/threshold changes or removed regression assertions. The compiler-only LE reader refactor in SDK fixes an observed macOS CI type-check blocker without changing byte semantics.

## Final local execution

- `python -m pytest -q`: **166 passed, 149 subtests passed**, 17.84s. Includes 86 per-schema PII fixtures, not 86 live external tool executions.
- `python eval/run_eval.py --offline`: **510 PASS**, exit 0. Existing assertions retained; fixture versions and output paths updated to the enforced contract.
- SDK `python -m unittest discover -s contracts/tests -q`: **14 passed**.
- Full local logs are in `evidence/`; macOS CI is tracked on SDK PR #84 and recorded separately after its actual outcome.

## Actual macOS CI

SDK code commit `5178552738b4bfa0ec8b7be8a17de3a7278f421b`: [run 35195407412](https://github.com/1494389516/cloudphone-risk-detector/actions/runs/35195407412), job 105117339133 **SUCCESS**. macOS 14 runner built the real package (65.19s); selected FusionTransportTests/FusionGraphTests/GraphModuleTests **25 tests, 0 failures**; Python **14 tests PASS**. Earlier CI runs 35194773165 and 35195077191 failed on a compiler expression limit and a non-exhaustive new error switch, respectively; both were fixed and the same gate rerun. This is host/selected-suite evidence, not a full native or real-device safety claim.

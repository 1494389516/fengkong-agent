# vNext implementation and acceptance status

Baseline: `af70f04f4d0706bad92f5944603eab3ed5fca1cf`.
This is a staged implementation, not a certification of the entire design or a
claim of production/business effectiveness. No production credentials, records,
paid generators or embedding experiments were used.

| Stage | Implemented and locally exercised | Remaining acceptance / scope |
|---|---|---|
| 01 | Separate partitioned Agent state/audit roots; read-only business locks unchanged; controller capacity mount/argument and real CLI validation | Docker/UID10001 mount gate added to CI, unavailable locally |
| 02 | HTTP returns after decision transaction; independent authenticated projector, transactional cursor/receipts and backlog metrics | Production throughput and restore/retention operations need deployment validation |
| 03 | Immutable revision table, tasks per revision, bounded shared-device evidence snapshot, auxiliary file hashes, captured SDK evidence, verified knowledge archives | Historical versions of auxiliary files, full DetectorCatalog/feature/model manifests are not available in existing data; explicitly unverified |
| 04 | Run attempts/epoch, token fencing, heartbeat/deadlines/retry cap, model/tool JSON step replay, stable private tokenizer salt, context binding | No claim of provider exactly-once; ambiguous calls interrupt. General sensitive-step human resume is not exposed; explicit new inference is separate |
| 05 | Persistent reservation/actual/estimated receipts, idempotent settlement, generator/verifier/embedding accounting and disabled hidden generator retries | Dollar pricing and non-token resource ledgers are not implemented; existing tool/graph bounds remain separate |
| 06 | JSON-schema argument checks before and after constraints, effective-argument audit, closed failures, lossless bounded SDK/RAG evidence views | Full field-dependency authorization graph, all-tool typed outputs and handle pagination remain future work; conservative untrusted→execute block remains |
| 07 | Typed scalar observation checks for subject/value/unit/time/negation; workflow/evidence/eligibility separation; historical model verdicts labeled unconfirmed | General natural-language factual correctness and graph aggregation claims still require independent review |
| 08 | Independent named consumer receipts/leases/DLQs; compatibility for legacy consumer; dirty-device batch shares scope rows and CommunityV1 graph | Immediate ingestion and temporal/shadow recomputation still have per-device work; no production latency benchmark |
| 09 | Validated fixed DAG, role/tool/scope intersection, durable device/graph/business collection; bounded corrective counterevidence retrieval retained | No separately calibrated expert model ensemble or demonstrated multi-agent benefit |
| 10 | Authenticated export of review + existing mined candidate + evaluation lineage; controller/publisher verify optional bundle provenance chain | Hashes do not authenticate external reviewers; full rule conversion/feature binding still relies on existing release gates; provenance is optional for legacy bundles |
| 11 | Isolated basic review web UI/API, current-revision/result binding, independent reviewer, idempotency, source/maturity-aware label eligibility | UI is syntax/API checked, not browser visually validated; arbitration and downstream training-label ingestion are not wired |
| 12 | Existing offline regression gates retained; new recovery/migration/review contracts; real Docker mount gate added | No reviewed business holdout dataset, production capacity envelope or authorized real-model experiment provided; quality, causal business gain and latency/cost remain unknown |

## Validation evidence

- Existing 22 architecture/governance/graph/token/RAG gate commands passed locally.
- New unittest discovery: 21 checks, 20 passed, one skipped because UID10001
  ownership mapping is unavailable in this container. Docker itself is absent.
- Compilation and review JavaScript syntax checks passed.
- No live provider calls were made. Scripted-generator integration is a plumbing
  test, not a generation-quality score.
- Regression examples cover same-case revision immutability, HTTP independence
  from failed projection, persisted-step replay after crash, stale-worker writes,
  8000 reserved / 1500 actual settlement, independent consumer DLQs, batch output
  equivalence, invalid claim subject/value/time/negation, stale reviews, and
  migration/archive tampering.

## Operational boundaries

SQLite is still a single-host adapter. Deploy roots and credentials before
activation. Keep the old database for rollback; migration never deletes it.
Do not truncate the append-only outbox. All historical snapshots are inspectable,
but capturing a current auxiliary file does not prove its historical validity.
A partial snapshot must never imply a clean entity. The basic workbench requires
TLS/authenticated ingress for remote use. Business labels and release authority
remain outside model output.

Do not report all twelve design stages as fully accepted until the final column
is addressed. These explicit remaining items are part of the delivery record.

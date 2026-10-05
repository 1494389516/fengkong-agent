# vNext implementation and acceptance status

Baseline: `af70f04f4d0706bad92f5944603eab3ed5fca1cf`.
This is a staged implementation, not a certification of the entire design or a
claim of production/business effectiveness. No production credentials, records,
paid generators or embedding experiments were used.

| Stage | Implemented and locally exercised | Remaining acceptance / scope |
|---|---|---|
| 01 | Separate partitioned Agent state/audit roots; read-only business locks unchanged; controller capacity mount/argument and real CLI validation | Real CI UID10001/read-only assertions passed on 2026-10-04; owner-aware cleanup fixed on 2026-10-05 (local Docker unavailable) |
| 02 | HTTP returns after decision transaction; independent authenticated projector, transactional cursor/receipts and backlog metrics | Production throughput and restore/retention operations need deployment validation |
| 03 | Immutable revision table, tasks per revision, bounded shared-device evidence snapshot, auxiliary file hashes, captured SDK evidence, verified knowledge archives | Historical versions of auxiliary files, full DetectorCatalog/feature/model manifests are not available in existing data; explicitly unverified |
| 04 | Run attempts/epoch, token fencing, heartbeat/deadlines/retry cap, model/tool JSON step replay, stable private tokenizer salt, context binding | No claim of provider exactly-once; ambiguous calls interrupt. General sensitive-step human resume is not exposed; explicit new inference is separate |
| 05 | Persistent reservation/actual/estimated receipts, idempotent settlement, generator/verifier/embedding accounting and disabled hidden generator retries | Durable tool/provider/search call receipts and pinned budget contracts added 2026-10-05; dollar pricing and cumulative scan/graph/byte ledgers remain separate |
| 06 | JSON-schema argument checks before and after constraints, effective-argument audit, closed failures, lossless bounded SDK/RAG evidence views | Full field-dependency authorization graph, all-tool typed outputs and handle pagination remain future work; conservative untrusted→execute block remains |
| 07 | Typed scalar observation checks for subject/value/unit/time/negation; workflow/evidence/eligibility separation; historical model verdicts labeled unconfirmed | General natural-language factual correctness and graph aggregation claims still require independent review |
| 08 | Independent named consumer receipts/leases/DLQs; compatibility for legacy consumer; dirty-device batch shares scope rows and CommunityV1 graph | Immediate ingestion and temporal/shadow recomputation still have per-device work; no production latency benchmark |
| 09 | Validated fixed DAG, role/tool/scope intersection, durable device/graph/business collection; bounded corrective counterevidence retrieval retained | No separately calibrated expert model ensemble or demonstrated multi-agent benefit |
| 10 | Authenticated export of review + existing mined candidate + evaluation lineage; controller/publisher verify optional bundle provenance chain; exporter requires current effective mature uncontested review | Hashes do not authenticate external reviewers; full rule conversion/feature binding still relies on existing release gates; provenance is optional for legacy bundles |
| 11 | Isolated basic review web UI/API, current-revision/result binding, independent reviewer, idempotency, source/maturity-aware label eligibility | Cross-run conflicts, independent arbitration, immutable review history, mature versioned label export and opt-in training adapter added 2026-10-05; real Chromium interaction/mobile layout checked. No automatic retraining or gold-holdout ingestion |
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


## Follow-up: 2026-10-05

- Checked main workflow run `37201873445`: all Python gates and the actual
  container UID/read-only assertions passed. The job failed only while the host
  runner tried to delete UID10001-owned temporary files. Cleanup now runs as the
  fixture owner, preserves test failure status, and does not loosen mount checks.
- Review conflicts cover separate inference attempts, not just one task. An
  arbiter must be independent of every reviewer and investigator; a new review
  invalidates the old review-set-bound arbitration. Export excludes unresolved,
  immature, superseded and cross-case conflicting labels. Review history cannot
  be updated/deleted through SQL. The CLI and training adapter preserve lineage
  without writing production labels or claiming gold-holdout eligibility.
- Persistent resource receipts account for tool attempts, knowledge searches and
  external provider steps, with no extra charge for committed replay. Budget
  changes and inconsistent reservation/settlement retries fail closed. Legacy
  runs lacking those receipts require explicit new inference.
- All 22 existing regression commands and the RAG scorecard gate passed locally.
  New unittest discovery: 25 checks, 24 passed, one host UID mapping skip.
  Real Chromium acceptance exercises arbitration submission, label export,
  safe rendering of HTML-like review text, and 390px mobile layout. This browser
  acceptance is now a CI gate. Compilation, JS syntax and diff checks passed.
- Production throughput, historical auxiliary provenance, general factual
  verification, full resource/pricing accounting, broader tool contracts and
  independently calibrated expert models remain outside these verified changes.
  No production holdout or live-provider effectiveness result is claimed.

# Targeted audit fixes — 2026-09-23

Baseline: f0c3a36eaa7c96562a4b9170109d31d3c2a1de43.

- F01: online account evidence uses a tenant/app/uid/time expression index and
  per-feature SQL predicates, including knowledge time and requested window. No
  application-wide history is materialized. Account budgets apply after selection.
  Unknown/global reads fail explicitly. Snapshot IDs bind selected evidence and
  remain absent on budget fallback. Full-history account metrics remain exact;
  an actually oversized account still degrades. Incremental historical aggregates
  are NOT implemented; do not describe this as unlimited lifetime account capacity.
- F02: after original-byte MAC verification, immutable mapping versions select
  trusted `field_mapping_scopes[version]` (`all` or legacy default `topLevel`).
  Recursive decoding includes array dictionaries and rejects per-level collisions.
  Payload limits: depth 16, decoded bytes 1 MiB. Provision a new version for `.all`;
  never change the meaning of an already deployed version.
- F03: attempted, successful and failed retrievals are distinct. Errors consume
  attempts, not successful counterevidence checks. Successful zero-hit checks count.
  Failed/pending retrieval makes report coverage incomplete, not balanced.
- F04: concurrent challenge issuance rejects the later request without invalidating
  the live challenge. Paired SDK serializes challenge/sign/submit/acknowledgement.
  One-use and monotonic counters remain enforced. Ambiguous responses require an
  identical upload retry; abandoned challenges expire after 120 seconds.

Deployment: build `events_account_order` during a maintenance window (call
`online_store.connect()` against the registered dataset before accepting traffic).
First creation scans existing events. Normal indexed reads remain budgeted; index
creation and database lock waits are not included in the feature execution budget.
The implementation digest changes, so re-admit/rebenchmark signed runtime bundles.
Coordinate Collector mapping configuration and SDK callback migration before use.

Validation: `python -m eval.audit_20260923` — 4 tests passed using production Python
modules and temporary SQLite, including two concurrent challenge requests.
`python -m eval.rag_eval` — 30/30 synthetic BM25 cases passed. No full HTTP deployment,
Swift compiler, native Keychain fault injection or genuine Apple App Attest run.
SDK test targets/workflow test configuration removed by the owner remain removed.

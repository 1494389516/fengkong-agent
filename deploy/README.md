# Isolated release and runtime deployment

# PostgreSQL production backend

The production Compose stack now requires separately provisioned PostgreSQL
service credentials and an offline schema migration. Follow
[POSTGRES.md](POSTGRES.md) before starting this stack or migrating existing data.
The mounted artifact/approval boundaries described below still apply.

This Compose stack separates ingress, decision, graph, investigation, review and release processes. It does not provision production secrets or claim live KMS validation. PostgreSQL roles and host bind mounts enforce storage boundaries; an operator must provision credentials and directory ownership.

| Process | Writable | Read only | Never mounted |
|---|---|---|---|
| collector | tenant ingestion/evidence database, collector-out | SDK registry, collector MAC keys, identity key, pinned Apple root | publisher private key, release credentials, bundles |
| runtime | tenant events/decision database, runtime-out | signed bundles, public key, runtime credential registry | release credentials, signing private key, release journal |
| investigator Agent | agent-out and its LKG cache | tenant observations, signed bundles, public key, Agent registry | release credentials, signing private key, release journal |
| controller | release journal | scoped release credential registry | signing private key, runtime dataset |
| publisher | signed bundles and atomic pointer | release journal, Ed25519 private key | Agent registry, runtime dataset |

The investigator profile deliberately grants `read` on production data. Mutable investigations/proposals must use a separately provisioned investigation workspace with selected read-only evidence inputs; never make the live tenant dataset writable by the Agent to enable proposal tools. Production `/approve` and `/deny` are refused in the Agent CLI. Independent release identities are used by the controller.

## Provisioning

From the repository root:

```sh
mkdir -p deploy/config deploy/secrets deploy/state/tenant deploy/state/collector-out deploy/state/runtime-out deploy/state/agent-out deploy/state/agent-state deploy/state/agent-audit deploy/state/journal deploy/state/bundles
```

Populate existing tenant data under `deploy/state/tenant`. Set ownership of writable state directories to UID/GID 10001. The runtime and Agent registries must be distinct files. `registry.example.json` and `credentials.example.json` intentionally contain invalid placeholders and already-expired expiry values; they cannot authorize anything. Provision random short-lived tokens via your identity/secrets service; store only SHA256(token) as registry keys. Do not put token values in git or command arguments.

`config/runtime-auth.json`: server-owned registry with tenant `a`, app `app`, absolute `data_dir: /tenant`, permissions such as `decisions.write` (business source) or `cases.read`. `config/agent-auth.json`: a separate operator identity with `permissions: ["agent.run"]` and `capabilities: ["read"]`. Use finite future Unix `expires_at`; input cannot replace the registry tenant/app/data path. Collector uses its own `config/collector-auth.json`, based on `collector-registry.example.json`. Its identities only have `reports.write`; they cannot invoke decisions. Runtime identities in `runtime-registry.example.json` only have `decisions.write` or `cases.read`, and cannot upload reports or enroll keys. Do not copy the same token into both registries.

`config/release-auth.json`: SHA256 token map to individual principals, each granted its actual `roles`, `scopes: ["tenant:a/app:app"]`, and finite future `expires_at`. Roles are `proposer`, `validator`, `shadow_runner`, `reviewer`, `release_controller`. The proposer must not approve its own proposal, even when an identity holds multiple roles.

Provision an Ed25519 PKCS8 PEM private key at `secrets/publisher.pem` and its matching public PEM at `config/publisher.pub`. A local development key can be generated with `openssl genpkey -algorithm ED25519`; this is not a production KMS integration. Private key owner UID 10001, mode 0400. Agent and runtime never mount it. For production replace local signing with your signing service integration and validate its policy separately.

## Release workflow

Build once:

```sh
docker compose -f deploy/compose.yaml build
```

Each controller invocation consumes one JSON request on standard input. Supply JSON from an operator-controlled file or secure pipe; do not commit it. For example:

```sh
docker compose -f deploy/compose.yaml run --rm -T controller < /secure/proposal-request.json
```

The request `operation` is `propose`, `transition`, or `rollback`, with the method's arguments and the short-lived `token`. Each `propose` returns a new UUID and digest. Transition order is `Validated`, `Shadow`, `Approved`, `Canary`, `Active`. Proofs must include `bundle_digest`, `baseline_activation`, `passed: true`, `evidence`, and canonical JSON SHA256 `evidence_digest`. Evidence includes matching `scope`, finite future `expires_at`, and positive `sample_count` for Shadow/Active. Active also requires `false_positive_delta` within the bundle's limit. Baseline changes require a fresh proposal and validation. Scope is tenant **and app**, exactly `tenant:a/app:app` in this sample.

Bundle content includes legacy release identifiers `rules`, `features`, `sdk_contract`, `challenge`, `fallback`, `code_digest`, `data_digest`, `canary_max_false_positive_delta` plus executable mappings `policy`, `strategy`, `model`, `feature`, `list`, `graph`, `versions`. `list.records` must explicitly be an array (an empty array means an intentionally empty list). `versions` identifies every runtime component. The repository integration tests construct executable bundles from the actual strategy/model files; an empty mapping is not a usable production model.

After an accepted activation:

```sh
docker compose -f deploy/compose.yaml run --rm -T publisher
docker compose -f deploy/compose.yaml up -d collector runtime
```

Publisher independently checks ordered gate history, evidence digests, bundle digest, and activation chaining, signs immutable `bundles/<activation-id>.json`, then atomically replaces signed `active.json`. Runtime verifies signatures using only the public key and captures the whole bundle per request. A corrupt new pointer retains a verified prior activation with explicit degradation; no verified prior activation fails closed. Rollback emits a new activation and requires running publisher again; it never reuses an activation ID.

Investigate with an Agent-only token provisioned into the launcher environment:

```sh
docker compose -f deploy/compose.yaml run --rm agent
```

Provide LLM configuration separately if interactive investigations require an external provider; none is embedded here. Agent tokens never grant release roles. Deployment secrets, generated state and `.env` are ignored by git.

## Verified locally and remaining environment checks

The tests run the publisher in a real separate Python process, verify emitted signatures, reject tampering, confirm new rollback activation, and exercise authenticated CLI scoping. Docker daemon execution, actual identity-provider token issuance, production file ownership and KMS permissions are deployment-environment acceptance checks; this repository does not pretend these were exercised on production infrastructure.

## Collector and Apple App Attest enrollment

Collector and runtime mount the same tenant directory read/write so verified report observations and business decisions can join by evidence reference without an SDK→LLM call. Agent mounts that directory read-only. Collector alone mounts:

- `secrets/collector-keys.json`: JSON mapping registered SDK key IDs to base64 key material of at least 32 bytes; keys must be provisioned securely and match the credential's permitted `key_ids`.
- `secrets/identity.key`: independently provisioned server identity namespace key (at least 32 random bytes). This never ships in the SDK and never mounts in the Agent.
- `config/apple-app-attest-root.pem`: an operator-verified pinned Apple App Attestation Root CA PEM. Obtain it through Apple's official PKI distribution and verify its fingerprint through your trusted provisioning process. Never accept a root certificate supplied in the enrollment request.

`app_attest_enrollment.app_id` is the actual Apple Team ID plus bundle ID, not the business `app` alias. Use `environment: production` for deployed App Attest keys; development attestations are rejected under this configuration. The SDK credential binds installation subject, generation, session digest, and permitted MAC key IDs. The examples are placeholders, not usable credentials.

With an authorized SDK bearer token, POST JSON to Collector port 8081:

1. `/attestation/challenge` with `{"purpose":"enrollment"}`. It returns a 120-second server challenge and `challenge_id`.
2. Generate an App Attest key and attestation over that challenge using the platform SDK, then `/attestation/enroll` with `{"challenge_id":"...","key_id":"...","attestation":"base64-CBOR-attestation"}`. Collector validates certificate chain against the pinned root, nonce binding, TeamID/bundle ID, environment and key ownership before enrollment. Challenge consumption and key insertion are atomic.
3. `/attestation/challenge` with `{"purpose":"assertion"}` provides a fresh server challenge for each required re-attestation. `/reports` carries the existing SDK network DTO, report signature, `attestation_key_id`, report-bound `attestation_assertion`, and `re_attestation_assertion` bound to the live server challenge. Assertion counters and challenge use are persisted atomically with evidence.
4. The authenticated business producer posts business events to runtime `/decisions` on port 8080 with report references. Its token never authorizes Collector operations.

A valid MAC or App Attest key is evidence of the verified signing/attestation properties; neither establishes that a human performed the action. Real Apple-issued attestation, physical-device behavior, and end-to-end device delivery must still pass your device acceptance run. Local tests use generated cryptographic fixtures and do not claim real-device validation.

## Agent storage and capacity contract

Provision `FK_AGENT_STATE_ROOT=/agent-state` and `FK_AGENT_AUDIT_ROOT=/agent-audit`
outside the evidence and signed release trees. Both are partitioned by the
canonical registered dataset hash. Agent checkpoints and output use state;
governance auditing and its chain lock use audit. Business mutation locks stay
in the business store; this does not grant production write capability.

Copy `compute-capacity.example.json` to `config/compute-capacity.json` and replace
its illustrative values with the operator's capacity envelope. The controller
mounts it read-only and validates it before reading requests. This configuration
is an admission target, not measured performance evidence.

## Asynchronous case projection

Run the `case-projector` service with its own short-lived registry/token granting
only `cases.project`, and the same tenant/app/data_dir binding. It reads the
committed decision outbox from a read-only evidence mount and commits its cursor,
deduplication receipt and cases in the Agent SQLite store. HTTP always reports
`investigation_projection_status=pending`; it never waits for the projector.
Runtime mounts Agent state read-only solely for authenticated case listing.
Do not delete/recreate or truncate the online outbox; the cursor assumes its
append-only row sequence. Use a migration before replacing an online database.

## vNext investigation and review operations

Provision `projector-auth.json` (`cases.project`), `investigator-auth.json`
(`cases.run`, `cases.read`, and an explicit `tools` allowlist), and
`reviewer-auth.json` (`cases.read`, `cases.review`) as separate identities.
All bind the same tenant/app evidence domain. Do not give the investigator
reviewer/release privileges. State directories must be owned by the deployment
UID, not world-writable.

For an installation with legacy cases in `online.sqlite3`, stop old investigation
workers and run `python -m agent.migrate_investigations` with projector credentials
and the new state-root configuration. It copies cases/tasks/receipts transactionally,
rejects conflicts and preserves the source. No automatic source deletion occurs.
Backup both stores before migration. Startup rejects an unmigrated legacy store.

Start projection with `python -m agent.case_worker`. The output includes pending
count and oldest pending age. A source outbox replacement/truncation fails closed.
Run a task with `FK_INVESTIGATOR_TOKEN` supplied securely and:

```
python -m agent.investigation_worker --task-id TASK_ID
```

Attempts have a 30-second lease, a 10-second heartbeat, a maximum 300-second
attempt deadline, three attempts and a 900-second retry horizon. All commits use
the current token. Completed model/tool steps replay; an unfinished provider call
requires review and is not automatically retried. For an explicitly authorized
new inference on the same revision (new accounting and task ID):

```
python -m agent.investigation_worker --new-run-case CASE_ID --revision 2
```

This is a **new run**, not continuation of an ambiguous billed call. A legacy
JSON CheckpointStore interrupt/resume is not a production authorization endpoint.
The investigator never uses its completed JSON files as completion authority.

`docker compose -f deploy/compose.yaml --profile investigate up -d case-review`
serves the review workbench at `http://127.0.0.1:8090`. Use an independently
provisioned short-lived reviewer credential. Remote deployments must put this
behind authenticated TLS ingress. The workbench keeps the token in memory only,
binds reviews to result digest/current revision and never writes gold labels or
production strategy. Delayed label maturity is represented explicitly.

For provenance export, use `python -m agent.strategy_artifacts` with an authorized
`FK_PROPOSER_TOKEN` (`cases.read`, `cases.propose`) and JSON stdin containing
`task_id`, `review_id`, `mining_ref` (existing local rule-mining path and SHA256),
and `candidate_id`. The mining path must be under that domain's shadow artifacts.
Transfer the resulting content-addressed chain to the controller as the bundle's
`investigation_provenance`. Controller and publisher validate its bindings;
existing validation, independent approval, canary, capacity and signature gates
still apply. This does not compile arbitrary model code into executable policy.

### Review conflicts, arbitration and training-label export

Reviews of **all inference runs for the same case revision** participate in one
review set. Conflicting verdicts block label export. `GET /api/case` exposes
`review_state`, including `reviews_digest`, conflicts and any effective resolution.
The workbench now offers arbitration when a conflict exists. Issue a separate,
short-lived identity with `cases.read` and `cases.arbitrate`; the original
investigator and participating reviewers cannot arbitrate their own case.

`POST /api/arbitrations` accepts `task_id`, `result_digest`, `reviews_digest`,
`verdict`, `note`, `matures_at`, and `request_id`. The service binds its decision
to the exact review set and current revision. Any subsequent review invalidates
that resolution. Review and arbitration records are append-only. Retrying the
same request ID with the same content returns the original record; changed
content is rejected.

A separate `cases.labels.export` permission authorizes
`POST /api/labels/export` with `{"as_of": <Unix timestamp>}`. The cutoff cannot
be in the future. Only current revisions, mature labels and resolved review
sets qualify. An unresolved or immature case blocks that entity, even if another
case has an eligible label. Conflicting labels across cases also block export.

For a versioned file suitable for an explicit downstream training input:

```sh
# Supply FK_LABEL_EXPORT_TOKEN through the deployment secret mechanism.
python -m agent.review_labels --as-of 1791158400
```

This writes a content-addressed JSON dataset under Agent state. Consumers call
`agent.case_review.training_labels(bundle, tenant, app)` to validate the digest,
scope, maturity and per-row provenance before using its labels. This is an
opt-in adapter: it does not overwrite `labels.json`, automatically retrain a
model, or add human-review labels to an independent gold holdout. Content hashes
detect changed exports; they do not authenticate files from an untrusted sender.

Strategy artifact export now requires the effective mature uncontested review
(or arbitration ID in `review_id`) for the current revision and the requested
inference result. It rejects stale, superseded, disputed and immature reviews.

### Persistent call budgets

New cases pin `max_provider_calls=24` together with token, tool and knowledge
search limits. Every attempted tool/provider step consumes a durable receipt;
a completed-step replay consumes none. A read interrupted before commit charges
again when retried, so a restart cannot reset its tool allowance. A changed
budget contract, reservation component/ceiling or settlement is rejected.
Legacy in-flight runs that already executed steps without resource receipts
must use the explicit new-inference operation; their unknown prior resource
usage cannot safely be reconstructed. Dollar pricing and cumulative database
scan/graph/byte accounting remain separate from these call receipts.

### Resource accounting and optional price ceilings

New snapshots include cumulative limits for event rows inspected, knowledge rows
loaded, JSON input/output bytes, graph nodes/edges constructed, reranker pairs,
and provider request/response JSON bytes. Existing per-query and per-graph limits
still apply. These receipts survive worker replacement; committed replay avoids
performing and charging the work again. Counts represent **logical JSON work**,
not physical SQLite pages, CPU cycles, HTTP headers or TLS traffic. Provider output
bytes can only be checked once a response arrives; they are not a streaming
transport-memory limit. Older immutable snapshots retain their existing contracts.

Set `FK_INVESTIGATION_PRICING` on the **case projector** to a read-only operator
configuration file. `deploy/investigation-pricing.example.json` describes the
schema only; its numbers are **not actual provider prices** and are not enabled
by default. With Compose, add the environment variable and a read-only mount of
your reviewed file through a deployment override. Worker credentials do not
need that file: the projector freezes the price contract in the snapshot.

Prices are positive integer nano-USD per token (1 USD = 1,000,000,000 nano-USD).
For each component, choose a conservative rate covering every permitted model,
input/output token category and cache tier. Reservations check both token and
price ceilings transactionally. Actual token usage releases unused reservation;
missing usage retains a conservative estimate. `cost_ledger` explicitly labels
these as operator price upper bounds, never verified invoices. Without a price
contract it reports `unpriced`, not zero cost. Updating prices affects new
snapshots; replay cannot swap the pinned price contract.

Budget exhaustion, lost leases and ambiguous provider requests must reach the
runtime even when an optional RAG evaluator/retriever normally falls back. A
provider failure after request start is conservatively interrupted; no automatic
retry assumes that the previous call was free. Failed tasks retain their token,
resource and cost ledger summaries in the stored result.

### Evidence-bound artifact authorization

The trajectory now preserves bounded, scope-bound result/field digests. UGC
fields remain `user_provided`; error results cannot provide authorizing fields.
Audit envelopes include tool effect, input schema digest, effective argument hash,
and any verified dependency digest.

An authenticated **host integration**, not an Agent tool, can call
`agent.tool_provenance.dispatch_authorized_artifact(context, tool, arguments,
bindings, expires_at=...)`. It requires `artifacts.create`, an active
`RequestScope` granting that tool, the existing explicit user intent, and an
explicit isolated `FK_AGENT_STATE_ROOT`. `bindings` maps every argument JSON
pointer to `{"ref": <trajectory evidence reference>, "path": <source pointer>}`.
The source field must be server evidence with exactly the requested value.
Obtain references from `governance.trajectory_snapshot()['evidence']`; do not
accept client-supplied trust labels as references.

Only the four existing regenerable chart tools support this exception to the
run-wide untrusted-content block. Production mutations remain blocked. Grants
expire, cannot cross principals/datasets/runs, and are invalid after changing an
argument or its evidence. Dispatch checks the final constrained arguments again.
The ordinary Agent/HTTP investigation path does not auto-mint these grants.
Charts use an Agent-state lock and atomic, hashed-name PNG writes, without
acquiring a write lock on the authoritative evidence volume.

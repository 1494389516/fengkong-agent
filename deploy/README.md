# Isolated release and runtime deployment

This compose example runs five independently permissioned processes. It does not provision production secrets or claim live KMS validation. Host bind mounts are the security boundary; directory ownership must be provisioned by an operator.

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
mkdir -p deploy/config deploy/secrets deploy/state/tenant deploy/state/collector-out deploy/state/runtime-out deploy/state/agent-out deploy/state/journal deploy/state/bundles
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

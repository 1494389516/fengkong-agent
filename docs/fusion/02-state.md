# Transactional event and decision boundary
Source SHA: 1548785eccd5500545e5850d7399ba4b64158c4c. Issues C13 C14 C15 G01 G02 G04.

SQLite FULL/WAL transaction stores decisions, business events and outbox. Same authenticated deployment tenant/app/event ID replays its immutable decision; different contents conflict. Feature evaluation uses only this domain's committed event prefix; the current event is committed once after evaluation. JSONL audit files are recoverable idempotent projections, never the authority.

FK_SERVE_SOURCE_KIND=business selects a credential-protected trusted business deployment; occurred time is retained for late events. Default legacy_client uses receipt time. Never share the business credential with an SDK. Body-supplied tenant/app/source/proof/aggregate fields are rejected. FK_SERVE_TENANT and FK_SERVE_APP identify the deployment. Dynamic multi-tenant routing is not implemented. Task scopes are bound to the deployment's resolved data directory and FK_SCOPE_TENANT.

Red: first six tests failed; later trusted source validation failed before implementation, and legacy migration guard failed with RuntimeError not raised before repair. Command: python -m pytest tests/test_fusion_state.py -q (10 passed). Coverage includes before/after-commit injected failures, next-request history, scope separation, actual HTTP business ingress, malformed type/huge numbers, corrupt store/capacity.

Migration gate: nonempty legacy decide_idemp.json blocks new online activation instead of silently forgetting deduplication. An operator must design/verify migration or drain its retention horizon before activation; no automatic deletion. Capacity rejects new legacy records instead of evicting live records. SQLite retention/capacity operational policy and process-kill/power-loss tests remain pending. Single-host serialized writer implementation, not distributed storage. Existing global intel/list/config files mean full multi-tenant service is not claimed.

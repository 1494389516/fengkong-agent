# Request and task isolation
Source SHA: 1548785eccd5500545e5850d7399ba4b64158c4c. Issues C16 C17 C18 C19 C20 C21.

Explicit expiring RequestScope plus user intent gates writes. ContextVars isolate request pack and scope; an Agent instance rejects overlapping ask calls and clears history/token mappings across identity changes. Persistent jobs bind submitter scope, child-tool capabilities and pack; four workers/64 backlog per process, leases/heartbeat/fencing and recovery; interrupted writes go to dead letter. Full tool results remain stored separately from LLM projections. Graph output has an explicit allowlist schema and typed-identity redaction.

Red: first five tests had four assertion failures and one missing-API error; graph output and concurrent-Agent tests failed before repair. Final targeted command python -m pytest tests/test_fusion_task_security.py -q: 13 passed. Original security tests retain assertions with explicit trusted-scope fixtures; no implicit authorization restored.

Limits: C21 only graph output has an explicit schema allowlist; other tools retain structured redaction. No new SSO service; scope must be constructed by a trusted caller. Per-process concurrency is not cluster-wide; real kill/restart fault injection remains pending. Deployment must bind FK_SCOPE_TENANT and resolved FK_DATA_DIR. CLI callers need explicit scope migration.

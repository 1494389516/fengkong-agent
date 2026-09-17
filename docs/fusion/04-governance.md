# Proposal and release governance
Source SHA: 1548785eccd5500545e5850d7399ba4b64158c4c. Issues C22 C23 C24 C25 C26 G06.

Monotonic durable proposal IDs, immutable proposal/change digest, shadow overrides/code/registry/baseline binding, threshold baseline CAS under lock and explicit approval principal. Whitelists require owner/reason/business scope and 1–30 day TTL, with exact UTC expiry. Legacy unsafe white records fail closed.

Standalone agent.control_plane is not an Agent tool. It authenticates separate roles and persists immutable bundle stages Proposal→Validated→Shadow→Approved→Canary→Active. Failed or mismatched proof, stale baseline, self-approval and breached canary budget block transitions. Rollback appends a fresh activation event. Production-mode legacy Agent approval is blocked.

Red: original seven assertions failed, controller's initial five tests failed before module implementation; null-bundle and precise-TTL tests also failed then passed. Final targeted python -m pytest tests/test_fusion_governance.py -q: 22 passed. Existing approval rollback regression also passed.

G06 remains partial: this records desired activations; runtime/deployer consumption, authenticated production metrics, KMS and mount/credential isolation require deployment work. Local digest is not an independent signature service; complete disk-write access remains in the trust boundary. Existing threshold CAS is not full cross-registry activation. No production credentials were created or supplied to Agent.

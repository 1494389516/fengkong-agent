# Time-scoped graph and integration evidence
Source SHAs: Agent 1548785eccd5500545e5850d7399ba4b64158c4c; SDK 6aeaf6783247258eba3f516efebd006561d4471c.
Issues C27 C28; C26 white-scope integration.

All IP relations are weak; missing device IDs never create shared entities. Explicit bounded as-of windows, resource-degree weakening and public traversal/truncation budgets. Components are association evidence, never malicious labels. Graph list lookup reuses the same as-of TTL service. Historical outputs do not attach present-day labels/intel/member verdicts.

Red: initial graph matrix had 14 failures including subtests; two further scope/budget failures were added before fixes. Targeted python -m pytest tests/test_fusion_graph.py -q: 9 passed, 10 subtests. Existing graph eval initially had seven failures because July fixtures fell outside today's window. Its fixture time is now explicitly pinned; original coverage retained with stronger future-leakage/IP counterexamples (12 checks passed).

Limits: asserted device IDs are not verified physical identities; storage still loads the event file before bounded graph construction. Final aggregate run details are recorded in FINAL_VALIDATION.md. issue_register.json preserves the source audit entries and adds implementation state; closed=false means no issue is silently treated as production-certified.

Final integration also carries independently discovered fixes: missing optional IP/device observations no longer cause a second-request HTTP 500; batch missing resource cardinality remains NaN while preserving numeric plotting dtype; explicit SDK/decision-request discriminators cannot enter the business event endpoint; expired or narrowed request scopes cannot retain prior privileged conversation history. Each received a failing regression before repair.

The existing offline evaluation retained and migrated its assertions to explicit authorization, scoped expiring white records, pinned historical graph fixtures, full task results, remote effective metadata, isolated online stores and real HTTP event history. No tests were deleted to obtain green results.

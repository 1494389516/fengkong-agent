# Native Swift / Collector interoperability

Pinned SDK: `f763c322b9e087102a2b7683fe20d78391540a91`.
Agent implementation baseline: `e2b4dec4346042a79ec843a48f459bbd6980144d`.

The macOS job builds an external SwiftPM executable against the entire,
unmodified SDK package. It calls the public `RiskSignal` Codable implementation,
`ReportEnvelope.create` and `toGrpcRequestBytes`. Python never recreates or
re-signs those native uploads.

Six uploads cover v2/v3 and no mapping / recursive mapping / top-level mapping.
Each includes hard false/true, soft, serverRequired, unavailable, tampered and
absent state, plus Unicode evidence and a non-ASCII report ID. They enter the
real authenticated `/reports` HTTP handler on loopback. Checks cover raw-byte
preservation, valid MACs, scoped signal references, privacy projection,
idempotent replay, exactly one integration event, lease-token fencing, and
the existing scripted durable investigation and evidence graph.

Reproduce on macOS with Swift and the Agent dependencies installed:

```sh
python scripts/run_swift_collector.py --sdk /path/to/pinned-sdk --output out/swift-wire.jsonl
FK_SWIFT_WIRE=out/swift-wire.jsonl python -m eval.swift_collector_interop
```

The producer rejects a changed SDK revision or dirty tree and clears previous
output before starting. Its artifact records the SDK SHA, Swift version,
producer hash and exact wire hash. Missing producer output is a failure, never
a skip or substitution with Python fixtures.

## Evidence and limits

The initial native encoder/signer + in-process Collector integration passed on
macOS in [run 37465285463](https://github.com/1494389516/fengkong-agent/actions/runs/37465285463),
Agent commit `d2f8009d01a6a2c5ae1039f0f5340074334fd9ce`.
The follow-up adds the real HTTP entrypoint; its own PR-head CI is authoritative.

Local existing gates: 12 SDK evidence regressions, architecture invariants,
graph pipeline and event leasing passed. vNext discovery: 34 checks, 33 passed,
one host UID mapping skip. No production decision logic or thresholds changed.

This verifies a native transport boundary, not an entire physical-device SDK
evaluation. Observations are synthetic; the compact outer payload is assembled
by the fixture, not the private full `CPRiskReport.Payload` builder. The SDK
`CollectorClient` TLS path, App Attest, v2h probe-conditioned derivation, armor,
real LLM quality, production capacity and device latency remain unverified.
The loopback HTTP transport does not replace production HTTPS acceptance.

## SDK PR #95 disposition

[#95](https://github.com/1494389516/cloudphone-risk-detector/pull/95) is open,
but its stale-report fix is already present in the pre-deletion main tree
`16543b971eaeb247e8720f8aa927d45fe97e90c0`: `experiments/ir-vmp/run.py`
writes a fresh UUID-tagged `RUNNING`, `vmp_verified=false` report atomically
before running tools, and records ordinary failures. The logic was incorporated
in #96 without making #95's original commit an ancestor of main.

#100 subsequently removed that runner in `410caf264846b53a0f5d777157c05a0c6db486e4`.
Recommendation: treat #95 as superseded, rather than merge it and restore a
deleted harness. This task does not close that PR or modify the SDK repository.

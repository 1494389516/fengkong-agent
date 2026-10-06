import CloudPhoneRiskKit
import Foundation

// These are synthetic observations encoded/signed by the unmodified SDK.
// No detector or App Attest result is fabricated by this producer.
let states: [RiskSignalState?] = [
    .hard(detected: false), .hard(detected: true), .soft(confidence: 0.4),
    .serverRequired, .unavailable, .tampered, nil,
]
let signals = states.enumerated().map { index, state in
    RiskSignal(id: index == 0 ? "sensor_replay_detected" : "private_signal_\(index)",
               category: "cloudphone", score: 12.5,
               evidence: ["note": "PRIVATE 中文 / café 😀"], state: state)
}
let encodedSignals = try JSONSerialization.jsonObject(with: JSONEncoder().encode(signals))
let payload: [String: Any] = ["sv": "6.5.0", "sg": encodedSignals,
                            "sm": "PRIVATE summary", "sr": ["is_fraud": true]]
let payloadBytes = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
let mappings: [PayloadFieldMapping?] = [nil,
    PayloadFieldMapping(version: "m1", mappings: ["sg": "xg", "i": "xi", "t": "xt", "d": "xd"], depthScope: .all),
    PayloadFieldMapping(version: "m2", mappings: ["sg": "xg"], depthScope: .topLevel),
]
// v2h depends on real anti-emulator probe flags. It is intentionally not
// neutralized or asserted here; v2/v3 exercise the portable transport boundary.
for version in ["v2", "v3"] {
    for mapping in mappings {
        let envelope = try ReportEnvelope.create(
            payloadData: payloadBytes, reportId: "interop-中文-\(UUID().uuidString)",
            sessionToken: "session", signingKey: String(repeating: "k", count: 32),
            keyId: "key", fieldMapping: mapping,
            config: ReportEnvelope.Config(signatureVersion: version))
        let wire = try envelope.toGrpcRequestBytes(
            context: GrpcReportContext(appId: "app", deviceId: "installation", scene: "login"))
        FileHandle.standardOutput.write(wire)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}

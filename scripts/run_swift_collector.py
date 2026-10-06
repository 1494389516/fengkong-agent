"""Run the real, pinned SDK public encoder/signer without modifying its checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

SDK_SHA = "f763c322b9e087102a2b7683fe20d78391540a91"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # An interrupted build must never leave an earlier success-looking output.
    args.output.unlink(missing_ok=True)
    manifest = args.output.with_suffix(".provenance.json")
    manifest.unlink(missing_ok=True)
    sdk = args.sdk.resolve()
    revision = subprocess.check_output(["git", "-C", str(sdk), "rev-parse", "HEAD"], text=True).strip()
    if revision != SDK_SHA or subprocess.check_output(["git", "-C", str(sdk), "status", "--porcelain"]):
        raise SystemExit("SDK must be the clean pinned revision: " + SDK_SHA)
    source = Path(__file__).resolve().parents[1] / "eval/swift_collector/main.swift"
    with tempfile.TemporaryDirectory(prefix="swift-collector-") as directory:
        root = Path(directory)
        (root / "Sources/Interop").mkdir(parents=True)
        shutil.copyfile(source, root / "Sources/Interop/main.swift")
        (root / "Package.swift").write_text('''// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "Interop", platforms: [.macOS(.v14)],
    dependencies: [.package(name: "CloudPhoneRiskKit", path: %s)],
    targets: [.executableTarget(name: "Interop", dependencies: [
        .product(name: "CloudPhoneRiskKit", package: "CloudPhoneRiskKit")])])
''' % json.dumps(str(sdk / "RiskDetectorApp")))
        swift_version = subprocess.check_output(["swift", "--version"], text=True).strip()
        result = subprocess.run(["swift", "run", "--package-path", str(root), "Interop"],
                                check=True, stdout=subprocess.PIPE)
    lines = result.stdout.splitlines()
    if len(lines) != 6 or any(json.loads(line).get("kind") != "sdk_report" for line in lines):
        raise SystemExit("Expected six native SDK upload records")
    args.output.write_bytes(result.stdout)
    manifest.write_text(json.dumps({"sdk_sha": revision, "swift": swift_version,
        "producer_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "wire_sha256": hashlib.sha256(result.stdout).hexdigest(), "records": len(lines),
        "scope": "native SDK signal Codable, envelope signing and HTTP DTO; synthetic measurements",
        "device_attestation_verified": False}, indent=2) + "\n")


if __name__ == "__main__":
    main()

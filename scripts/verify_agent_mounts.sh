#!/bin/sh
set -eu
# CI owns this temporary fixture. No production paths or secrets are mounted.
fixture=$(mktemp -d)
image_ready=0
cleanup() {
  result=$?
  trap - EXIT
  if [ "$image_ready" = 1 ]; then
    # The fixture's children belong to UID10001, not the hosted CI runner.
    # Remove them as their owner before removing the host-owned fixture root.
    docker run --rm --read-only --user 10001:10001 --cap-drop ALL \
      -v "$fixture/state:/agent-state" -v "$fixture/audit:/agent-audit" \
      fengkong-agent-mount-contract python -c '
import shutil
from pathlib import Path
for root in (Path("/agent-state"), Path("/agent-audit")):
    for child in root.iterdir():
        if child.is_dir() and not child.is_symlink(): shutil.rmtree(child)
        else: child.unlink()
' || result=1
  fi
  rm -rf "$fixture" || result=1
  exit "$result"
}
trap cleanup EXIT
mkdir -p "$fixture/evidence" "$fixture/release" "$fixture/state" "$fixture/audit"
chmod 755 "$fixture" "$fixture/evidence" "$fixture/release"
chmod 777 "$fixture/state" "$fixture/audit"
docker build -f deploy/Dockerfile -t fengkong-agent-mount-contract .
image_ready=1
docker run --rm --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp \
  -e FK_DATA_DIR=/evidence -e FK_AGENT_STATE_ROOT=/agent-state -e FK_AGENT_AUDIT_ROOT=/agent-audit \
  -e FK_RUNTIME_BUNDLE_DIR=/release \
  -v "$fixture/evidence:/evidence:ro" -v "$fixture/release:/release:ro" \
  -v "$fixture/state:/agent-state" -v "$fixture/audit:/agent-audit" \
  fengkong-agent-mount-contract python -c '
from pathlib import Path
from agent.tools import dispatch
from agent.durable import CheckpointStore, InvestigationCheckpoint
assert "error" not in dispatch("capability_registry", {})
CheckpointStore().save(InvestigationCheckpoint("run", "case", "start", {}))
for root in ("/evidence", "/release"):
    try: Path(root, "forbidden").write_text("x")
    except OSError: pass
    else: raise AssertionError("authority mount is writable")
assert list(Path("/agent-audit").rglob("governance_audit.jsonl"))
assert list(Path("/agent-state").rglob("run.json"))
print("UID10001 and read-only mount contract passed")
'

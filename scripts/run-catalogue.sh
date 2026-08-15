#!/usr/bin/env sh
# Run the labeled attack catalogue and score it against Suricata's eve.json.
#
# Because eve.json lives in the `suricata-logs` named volume (not on the host
# filesystem), this script copies it out with `docker compose cp` before
# scoring — the plan's `--eve /var/log/suricata/eve.json` path only works when
# scoring on a Linux host that can read the volume directly.
#
# Requires: the stack already `up` with a WORKING capture. On Windows/macOS the
# scorer will (correctly) report INVALID_RUN until M1's namespace-shared
# Suricata lands — a dead capture must not masquerade as 0/10 detection.
#
# Usage:
#   SCENARIO=all ./scripts/run-catalogue.sh
#   SCENARIO=A01,A04 ./scripts/run-catalogue.sh
set -eu

SCENARIO="${SCENARIO:-all}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="runs/${RUN_ID}"
mkdir -p "${RUN_DIR}"

echo "[run-catalogue] run_id=${RUN_ID} scenario=${SCENARIO}"

# 1) Launch the catalogue (one-shot). The container writes the manifest into
#    runs/<RUN_ID>/manifest.json via the ./runs bind mount.
SCENARIO="${SCENARIO}" MODE=catalogue \
  docker compose --profile attack run --rm \
    -e RUN_ID="${RUN_ID}" \
    attack-sim

# 2) Copy Suricata's eve.json out of the suricata-logs volume.
echo "[run-catalogue] copying eve.json out of the suricata-logs volume"
docker compose cp suricata:/var/log/suricata/eve.json "${RUN_DIR}/eve.json"

# 3) Score. Stamp the pinned ruleset/Suricata versions if available.
RULESET_VERSION="$(docker compose exec -T suricata sh -c 'cat /var/lib/suricata/rules/version 2>/dev/null || echo unknown' 2>/dev/null || echo unknown)"
SURICATA_VERSION="$(docker compose exec -T suricata suricata -V 2>/dev/null | sed -n 's/.*version //p' | head -n1 || echo unknown)"

python -m netguard.scorer \
  --manifest "${RUN_DIR}/manifest.json" \
  --eve      "${RUN_DIR}/eve.json" \
  --baseline eval/baseline.json \
  --ruleset-version "${RULESET_VERSION}" \
  --suricata-version "${SURICATA_VERSION}" \
  --out "${RUN_DIR}/scorecard.json"

echo "[run-catalogue] scorecard -> ${RUN_DIR}/scorecard.json"

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

# 3) Score. Stamp the pinned ET Open version (from the lockfile) + Suricata.
RULESET_VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' eval/ruleset.lock 2>/dev/null | head -n1)"
RULESET_VERSION="${RULESET_VERSION:-unknown}"
SURICATA_VERSION="$(docker compose exec -T suricata suricata -V 2>/dev/null | sed -n 's/.*version //p' | head -n1 || echo unknown)"

# Prefer a host Python; fall back to a throwaway Python container (the scorer is
# pure stdlib, so no image build or pip install is needed). This keeps the run
# working on hosts with no Python installed.
score() {
  # Test that the interpreter actually RUNS, not just that it is on PATH — the
  # Windows Store `python`/`python3` shims resolve on PATH but error on use.
  for py in python3 python; do
    if "$py" -c 'import sys' >/dev/null 2>&1; then
      "$py" -m netguard.scorer "$@"
      return $?
    fi
  done
  echo "[run-catalogue] no working host Python; scoring in a python:3.12-alpine container"
  MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/w -w /w python:3.12-alpine python -m netguard.scorer "$@"
}

score \
  --manifest "${RUN_DIR}/manifest.json" \
  --eve      "${RUN_DIR}/eve.json" \
  --baseline eval/baseline.json \
  --ruleset-version "${RULESET_VERSION}" \
  --suricata-version "${SURICATA_VERSION}" \
  --out "${RUN_DIR}/scorecard.json"

echo "[run-catalogue] scorecard -> ${RUN_DIR}/scorecard.json"

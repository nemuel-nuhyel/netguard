#!/usr/bin/env sh
# The detection regression gate (plan §5.3, §6 "detection" stage), meant to run
# on a Linux CI runner with Docker. Brings up the lab plane, waits for a LIVE
# capture (proven by demo-sid alerts), runs the labeled catalogue, and scores it
# against eval/baseline.json. The scorer exits non-zero — failing the build — if
# recall drops below or the false-positive count rises above the committed
# baseline, or if the capture was dead (INVALID_RUN).
set -eu

echo "::group::bring up lab plane"
docker compose up -d --build suricata traffic-generator
echo "::endgroup::"

echo "::group::wait for live capture (demo-sid alerts)"
live=0
for i in $(seq 1 60); do
  if docker compose exec -T suricata sh -c \
       'grep -qE "\"signature_id\":100000[1-4]" /var/log/suricata/eve.json 2>/dev/null'; then
    echo "capture live after ~$((i*5))s"
    live=1
    break
  fi
  sleep 5
done
if [ "$live" -ne 1 ]; then
  echo "FAIL: no demo-sid alerts after 300s — capture never came up"
  docker compose logs suricata | tail -40
  exit 1
fi
echo "::endgroup::"

echo "::group::run catalogue + score (gates on baseline)"
# run-catalogue.sh runs the catalogue, copies eve.json out of the volume, and
# invokes the scorer with --baseline; its exit status is the gate. Capture it
# explicitly (set -e would otherwise abort before we can report it).
if SCENARIO=all ./scripts/run-catalogue.sh; then
  rc=0
else
  rc=$?
  echo "FAIL: detection gate failed (scorer exit $rc) — recall below or FP above baseline, or dead capture"
fi
echo "::endgroup::"

exit "$rc"

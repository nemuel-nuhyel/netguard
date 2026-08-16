#!/usr/bin/env sh
# Assert that key config/source files stay TRACKED — the guard against F2/ADR-006,
# where a blanket .gitignore silently swallows a config-centric project. Also
# assert that real secrets stay IGNORED. Runs in pre-commit and CI.
set -eu

fail=0

# These must NOT be ignored (a broad wildcard returning would hide the project).
must_track="
docker-compose.yml
services/suricata/suricata.yaml
services/suricata/rules/local.rules
services/suricata/rules/demo.rules
monitoring/prometheus/prometheus.yml
monitoring/loki/loki-config.yml
monitoring/promtail/promtail-config.yml
monitoring/grafana/provisioning/datasources/datasources.yml
netguard/scorer.py
services/attack-sim/run_catalogue.py
eval/baseline.json
eval/ruleset.lock
"

for f in $must_track; do
  if git check-ignore -q "$f"; then
    echo "FAIL: $f is git-ignored but must be tracked"
    fail=1
  fi
done

# These MUST stay ignored (secrets / runtime data).
must_ignore="
.env
services/wireguard/config/wg0.conf
docker/wireguard/config/peer1/peer1.conf
runs/example/scorecard.json
"

for f in $must_ignore; do
  if ! git check-ignore -q "$f"; then
    echo "FAIL: $f is NOT ignored but must be (secret/runtime path)"
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "[check-gitignore] ok — tracked files tracked, secrets ignored"
fi
exit "$fail"

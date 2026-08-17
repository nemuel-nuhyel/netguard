#!/usr/bin/env sh
# Assert that key config/source files stay visible to Git — the guard against
# F2/ADR-006, where a blanket .gitignore silently swallows a config-centric
# project. Also assert that real secrets and generated data stay ignored. Runs
# in pre-commit and CI.
set -eu

fail=0

# These must NOT be ignored (a broad wildcard returning would hide the project).
must_track="
.gitattributes
.env.example
docker-compose.yml
services/attack-sim/.dockerignore
services/traffic-generator/.dockerignore
services/suricata/suricata.yaml
services/suricata/rules/local.rules
services/suricata/rules/demo.rules
monitoring/prometheus/prometheus.yml
monitoring/prometheus/rules/netguard-alerts.yml
monitoring/loki/loki-config.yml
monitoring/promtail/promtail-config.yml
monitoring/grafana/provisioning/datasources/datasources.yml
netguard/scorer.py
services/attack-sim/run_catalogue.py
eval/baseline.json
eval/ruleset.lock
scripts/check-hardening.sh
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
.env.local
.env.production
.env.test.local
.envrc
services/wireguard/config/wg0.conf
docker/wireguard/config/peer1/peer1.conf
runs/example/scorecard.json
tests/__pycache__/test_scorer.pyc
.ruff_cache/example
private/signing-key.pem
private/client.p12
"

for f in $must_ignore; do
  if ! git check-ignore -q "$f"; then
    echo "FAIL: $f is NOT ignored but must be (secret/runtime path)"
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "[check-gitignore] ok — required sources visible; secrets and generated data ignored"
fi
exit "$fail"

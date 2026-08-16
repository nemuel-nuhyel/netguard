#!/usr/bin/env sh
# Compile-test the hand-maintained rule files (local.rules + demo.rules) with
# `suricata -T`. This is offline and needs no ET Open volume — it validates only
# the files in the repo. The full merged ruleset (ET Open + local + demo) is
# validated when the stack starts, since Suricata loads suricata.yaml then.
set -eu

for rules in local.rules demo.rules; do
  echo "[validate-rules] testing services/suricata/rules/${rules}"
  docker run --rm \
    -v "$PWD/services/suricata/rules/${rules}:/etc/suricata/rules/${rules}:ro" \
    jasonish/suricata:7.0.7 \
    -T -S "/etc/suricata/rules/${rules}"
done

echo "[validate-rules] ok"

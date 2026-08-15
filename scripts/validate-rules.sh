#!/usr/bin/env sh
set -eu

docker run --rm \
  -v "$PWD/services/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
  -v "$PWD/services/suricata/rules/local.rules:/etc/suricata/rules/local.rules:ro" \
  jasonish/suricata:7 \
  -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules

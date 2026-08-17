#!/usr/bin/env sh
# Guard exposure, supply-chain, and log-pipeline controls against drift:
#   1. Prometheus and Grafana are published on host loopback only.
#   2. Grafana reads its admin password from a Docker secret, not its env.
#   3. The privileged WireGuard image is immutable and no image uses :latest.
#   4. WireGuard peers can reach the private Grafana management network.
# Runs in pre-commit and CI.
set -eu

COMPOSE="docker-compose.yml"
LOKI_CONFIG="monitoring/loki/loki-config.yml"
PROMETHEUS_CONFIG="monitoring/prometheus/prometheus.yml"
PROMETHEUS_RULES="monitoring/prometheus/rules/netguard-alerts.yml"
fail=0

require_pattern() {
  pattern="$1"
  message="$2"
  file="${3:-$COMPOSE}"
  if ! grep -Eq "$pattern" "$file"; then
    echo "FAIL: $message"
    fail=1
  fi
}

forbid_pattern() {
  pattern="$1"
  message="$2"
  if grep -Eq "$pattern" "$COMPOSE"; then
    echo "FAIL: $message"
    fail=1
  fi
}

require_count() {
  pattern="$1"
  expected="$2"
  message="$3"
  actual="$(grep -Ec "$pattern" "$COMPOSE" || true)"
  if [ "$actual" -ne "$expected" ]; then
    echo "FAIL: $message (found $actual, expected $expected)"
    fail=1
  fi
}

require_pattern '^[[:space:]]+- "127\.0\.0\.1:9090:9090"' \
  "Prometheus must bind host port 9090 to 127.0.0.1"
require_pattern '^[[:space:]]+- "127\.0\.0\.1:3000:3000"' \
  "Grafana must bind host port 3000 to 127.0.0.1"
require_count '9090:9090' 1 "Prometheus must have exactly one host-port publication"
require_count '3000:3000' 1 "Grafana must have exactly one host-port publication"

require_pattern '^[[:space:]]+GF_SECURITY_ADMIN_PASSWORD__FILE: /run/secrets/grafana_admin_password$' \
  "Grafana must read its admin password from /run/secrets/grafana_admin_password"
require_pattern '^[[:space:]]+environment: GRAFANA_ADMIN_PASSWORD$' \
  "the Grafana secret must be sourced from GRAFANA_ADMIN_PASSWORD"
require_pattern "grep -Fxq 'change-this-local-password'" \
  "Grafana must reject a missing or published example password"
# This regex intentionally matches literal Compose dollar escapes.
# shellcheck disable=SC2016
require_pattern 'bytes=\$\$\(wc -c < "\$\$secret"\)' \
  "Grafana must enforce a minimum password length"
forbid_pattern '^[[:space:]]+GF_SECURITY_ADMIN_PASSWORD:' \
  "Grafana admin password must not be exposed in the container environment"
require_pattern '^GRAFANA_ADMIN_PASSWORD=$' \
  "the env template must not publish a working password" ".env.example"

require_pattern '^[[:space:]]+image: lscr\.io/linuxserver/wireguard@sha256:[0-9a-f]{64}$' \
  "the privileged WireGuard image must be pinned by sha256 digest"
forbid_pattern '^[[:space:]]+image:.*:latest([[:space:]]|$)' \
  "container images must not use the floating :latest tag"
require_pattern 'WG_ALLOWED_IPS:-10\.10\.0\.0/24,10\.50\.0\.0/24,10\.200\.0\.0/24' \
  "default WireGuard peer routes must include the lab, management, and VPN networks"

require_pattern '^[[:space:]]+retention_enabled: true$' \
  "Loki retention compaction must be enabled" "$LOKI_CONFIG"
require_pattern '^[[:space:]]+retention_period: 168h$' \
  "Loki must enforce the seven-day retention period" "$LOKI_CONFIG"
require_pattern '^[[:space:]]+ingestion_rate_mb: [1-9][0-9]*$' \
  "Loki must enforce an explicit ingestion rate" "$LOKI_CONFIG"
require_pattern '^rule_files:$' \
  "Prometheus must load repository alert rules" "$PROMETHEUS_CONFIG"
require_pattern 'alert: NetGuardLokiIngestionRejected$' \
  "Prometheus must alert when Loki rejects security events" "$PROMETHEUS_RULES"
require_pattern 'sum\(increase\(loki_discarded_samples_total\[5m\]\)\) > 0$' \
  "Prometheus must alert on every Loki discarded-sample reason" "$PROMETHEUS_RULES"
require_pattern 'alert: NetGuardLokiFilesystemPressure$' \
  "Prometheus must alert on Loki filesystem pressure" "$PROMETHEUS_RULES"

if [ "$fail" -eq 0 ]; then
  echo "[check-hardening] ok - exposure, secret, pinning, routing, retention, and alert controls enforced"
fi
exit "$fail"

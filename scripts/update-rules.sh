#!/bin/sh
# Fetch the Emerging Threats Open ruleset with suricata-update and PIN it, so a
# scored run is reproducible and self-describing (plan §4.1, §5.2, ADR-002).
#
# Runs inside the jasonish/suricata image (which ships suricata-update). The
# `suricata-rules` init service invokes it before Suricata starts; the fetched
# rules land in the shared suricata-rules volume at /var/lib/suricata/rules.
#
# Pinning model: ET Open is a rolling ruleset with no semver, so we pin by
# CONTENT. Every fetch records the exact sha256, rule count and date into
# eval/ruleset.lock; the scorer stamps that version string into each scorecard.
# A deliberate ruleset bump is a visible diff to the lockfile. Set VERIFY=1 to
# HARD-FAIL when the fetched content drifts from a committed non-"pending" pin
# (use in CI to prove a scored run is reproducible).
set -eu

SURICATA_VERSION="${SURICATA_VERSION:-7.0.7}"
OUT_DIR="${OUT_DIR:-/var/lib/suricata/rules}"
LOCK="${LOCK:-/eval/ruleset.lock}"

echo "[update-rules] fetching ET Open for Suricata ${SURICATA_VERSION}"
suricata-update update-sources
suricata-update enable-source et/open
suricata-update \
  --suricata-version "${SURICATA_VERSION}" \
  --no-test --no-reload \
  --data-dir /var/lib/suricata \
  -o "${OUT_DIR}"

RULES="${OUT_DIR}/suricata.rules"
if [ ! -f "${RULES}" ]; then
  echo "[update-rules] ERROR: ${RULES} was not produced" >&2
  exit 1
fi

HASH="$(sha256sum "${RULES}" | cut -d' ' -f1)"
COUNT="$(grep -cE '^[[:space:]]*(alert|drop|reject|pass)[[:space:]]' "${RULES}" || true)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DAY="${DATE%T*}"
VERSION="ET-Open/suricata-${SURICATA_VERSION}/${DAY}"

# Reproducibility gate: compare against a committed pin, if one exists.
if [ -f "${LOCK}" ]; then
  PINNED="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "${LOCK}" | head -n1)"
  if [ -n "${PINNED}" ] && [ "${PINNED}" != "pending" ] && [ "${PINNED}" != "${HASH}" ]; then
    echo "[update-rules] WARNING: ET Open content drifted from the committed pin"
    echo "    pinned : ${PINNED}"
    echo "    fetched: ${HASH}"
    if [ "${VERIFY:-0}" = "1" ]; then
      echo "[update-rules] VERIFY=1 -> failing on ruleset drift" >&2
      exit 2
    fi
  fi
fi

mkdir -p "$(dirname "${LOCK}")"
cat > "${LOCK}" <<EOF
{
  "source": "et/open",
  "suricata_version": "${SURICATA_VERSION}",
  "fetched_at": "${DATE}",
  "version": "${VERSION}",
  "sha256": "${HASH}",
  "rule_count": ${COUNT:-0}
}
EOF

echo "[update-rules] pinned ${VERSION}"
echo "[update-rules]   rules: ${COUNT}   sha256: ${HASH}"
echo "[update-rules]   lock:  ${LOCK}"

#!/usr/bin/env sh
# Guard against the closed loop returning (F3 / ADR-003 / plan §5.3):
#   1. The self-referential demo sids live ONLY in demo.rules, never in
#      local.rules (where they would be counted as real detection).
#   2. demo.rules' sid set matches catalogue.py:DEMO_SIDS, so the scorer's
#      exclusion list stays in sync with the rules actually loaded.
# Runs in pre-commit and CI.
set -eu

DEMO_RULES="services/suricata/rules/demo.rules"
LOCAL_RULES="services/suricata/rules/local.rules"
CATALOGUE="services/attack-sim/catalogue.py"

fail=0

# Sids declared in demo.rules, sorted.
demo_sids="$(grep -oE 'sid:[0-9]+' "$DEMO_RULES" | grep -oE '[0-9]+' | sort -u | tr '\n' ' ' | sed 's/ *$//')"

# DEMO_SIDS from catalogue.py, sorted.
cat_sids="$(grep -oE 'DEMO_SIDS *= *\[[0-9, ]*\]' "$CATALOGUE" | grep -oE '[0-9]+' | sort -u | tr '\n' ' ' | sed 's/ *$//')"

if [ "$demo_sids" != "$cat_sids" ]; then
  echo "FAIL: demo.rules sids [$demo_sids] != catalogue DEMO_SIDS [$cat_sids]"
  fail=1
fi

# No demo sid may appear in local.rules.
for sid in $demo_sids; do
  if grep -qE "sid:$sid\b" "$LOCAL_RULES"; then
    echo "FAIL: demo sid $sid found in local.rules — it must live only in demo.rules"
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "[check-demo-rules] ok — demo sids [$demo_sids] isolated and in sync"
fi
exit "$fail"

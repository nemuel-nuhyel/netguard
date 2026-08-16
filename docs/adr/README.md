# Architecture Decision Records

Each ADR records a decision, the context that forced it, and the consequences we accepted. They are the "why" behind the code; the "what" is in [`../ENGINEERING_PLAN.md`](../ENGINEERING_PLAN.md). Status is `Accepted` unless noted.

---

## ADR-001 — Namespace-shared Suricata over host mode

**Context.** `network_mode: host` with `-i any` captures the Docker Desktop backing VM's interfaces, not the lab bridge, so on Windows/macOS Suricata ran healthy and inspected nothing (finding F4). The author develops on Windows.

**Decision.** Run Suricata in the monitored app's network namespace (`network_mode: service:monitored-app`) and inspect its `eth0`.

**Consequences.** Capture is portable and identical on Linux/Windows/macOS, and scopes the IDS to the asset it protects — the right scope for a single-target lab. The trade-off: traffic that never reaches the monitored app (e.g. DNS to the resolver) is out of view, which is why catalogue entry A08 is a documented miss. Multi-target capture returns as an option for a Linux-host deployment.

---

## ADR-002 — Emerging Threats Open alongside `local.rules`

**Context.** A hand-written rule file cannot approach real-world coverage.

**Decision.** Manage ET Open with `suricata-update`, pinned by content hash in `eval/ruleset.lock`; keep a small `local.rules` for gaps ET Open misses.

**Consequences.** Broad, credible coverage for free, reproducible per scored run. ET Open is a rolling ruleset, so the pin is by content hash and the CI gate is not hermetic — a future ET change that drops coverage fails the gate until investigated (see ADR-004).

---

## ADR-003 — Self-referential rules demoted to `demo.rules`, never scored

**Context.** All four original rules matched strings the project's own traffic generator emits (its user-agent, `/admin`, `example.com`). Counting them as "detection" is a closed loop that made the original claim hollow (F3).

**Decision.** Move sids `1000001–1000004` to `demo.rules`; the scorer excludes them from every detection metric and uses them only as capture-liveness proof. `check-demo-rules.sh` asserts they stay isolated and in sync with the scorer's exclusion list.

**Consequences.** The score reflects detection of traffic the project does not control. The pipeline smoke-test value of those rules is retained without contaminating the measurement.

---

## ADR-004 — Build the scorer before broadening the rules

**Context.** The tempting mistake is to add ET Open, watch alerts appear, and declare success — the original mistake in a new form. "More alerts" is not "better detection" without a denominator.

**Decision.** The scorer and catalogue came first; every rule change is measured as a delta against a committed baseline (`eval/baseline.json`).

**Consequences.** Detection progress is a reviewable number (0 → 7/10 ET-only → 9/10 with author rules), not an assertion. An intentional improvement bumps the baseline in the same commit.

---

## ADR-005 — Recall at a fixed false-positive budget is the headline metric

**Context.** Alert volume rewards noise; a personal SOC that cries wolf gets muted.

**Decision.** Report recall together with precision and a false-positive count over labeled negative controls. The gate fails if FP rises, not just if recall falls.

**Consequences.** A run that fires 5,000 alerts and misses the SQLi scores worse than one that fires 12 and catches everything. Precision is a first-class number, and the negative controls (N01–N04) make the FP surface explicit.

---

## ADR-006 — `.gitignore` by specific secret names, never blanket wildcards

**Context.** A blanket `*.conf` / `**/config/*` silently swallows a config-centric project the moment it grows (F2). A separate bug: inline comments on ignore lines are literal, silently disarming the patterns.

**Decision.** Ignore secrets by specific name/path; keep comments on their own lines; assert key files stay tracked with `check-gitignore.sh` in CI and pre-commit.

**Consequences.** Config is version-controlled; secrets are not; the failure cannot silently return.

---

## ADR-007 — GitHub Actions, not GitLab CI

**Context.** The 2.0 proposal specified GitLab CI, but the code lives on GitHub.

**Decision.** Implement the pipeline as GitHub Actions.

**Consequences.** CI runs where the code is; the success metric ("zero secret leakage, measured every commit") becomes real via gitleaks.

---

## ADR-008 — Loopback binds for Prometheus/Grafana *(Proposed — open)*

**Context.** Prometheus and Grafana bind `0.0.0.0` with weak/no auth (F5); anyone on the same LAN can read every metric.

**Decision.** Bind both to `127.0.0.1`, reachable via the WireGuard tunnel or an SSH forward; move Grafana's admin password to a Docker secret.

**Status.** Open — the remaining M1 hardening. Tracked in the README's *Known hardening gaps* and threat-model invariant 6.

---

## ADR-009 — Attack simulator profile-gated and lab-network-only

**Context.** The everyday `docker compose up` must stay benign, and the simulator must never reach the monitoring plane.

**Decision.** `profiles: [attack]` (opt-in) and attachment to `netguard-lab` only.

**Consequences.** The default demo is safe; invariant 1 holds by construction. Nothing the simulator does is a real exploit — the nginx target is unmodified and the payloads are detection triggers.

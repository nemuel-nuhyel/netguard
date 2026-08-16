# NetGuard

**A containerized network-security monitoring lab whose detection is _measured_, not asserted.**

Most portfolio IDS labs light up a dashboard with traffic they generate for themselves and call it "detection." NetGuard instead launches a labeled catalogue of real attack shapes against a monitored target, joins the alerts Suricata actually produced against that catalogue, and reports a **scorecard** — recall, precision, false positives, and mean-time-to-detect — pinned to an exact ruleset version and regression-gated in CI.

## The number

Latest scored run — **Emerging Threats Open + two author rules**, verified end-to-end on a GitHub Actions runner:

| | |
|---|---|
| **Recall** | **9 / 10** attack techniques detected |
| **Precision** | **1.0** (no attack-class alert on benign traffic) |
| **False positives** | **0** across four negative controls |
| **MTTD** | ~0.01 s median (launch → first alert) |
| **Ruleset** | `ET-Open/suricata-7.0.7` (52,328 rules, content-pinned in `eval/ruleset.lock`) |

```
ID   TECHNIQUE                    ATT&CK      RESULT
A01  SYN port scan                T1046       DETECTED
A02  Service/version scan         T1046       DETECTED
A03  Directory enumeration        T1083       DETECTED
A04  SQL injection                T1190       DETECTED
A05  Reflected XSS                T1059       DETECTED
A06  Command injection            T1190       DETECTED
A07  HTTP auth brute force        T1110       DETECTED
A08  DNS tunneling                T1071.004   missed  ← documented (out of capture scope)
A09  C2 beaconing                 T1071       DETECTED   (author rule)
A10  Exfiltration over HTTP       T1048       DETECTED   (author rule)
```

**The miss is the most honest line in this repo.** A08 is not a ruleset gap — the simulator's DNS never traverses the monitored app's network namespace, so a namespace-scoped IDS cannot see it (see [Stated limitations](#stated-limitations)). It is reported as a miss rather than hidden, because a detector you can't trust to admit a gap is a detector you can't trust.

## Why this is different

The original lab had four Suricata rules, and every one matched a string the project's own traffic generator emitted: its `User-Agent`, its `/admin` probe, its `example.com` lookup. Generator → rule → dashboard → generator: a closed loop that proves a *pipeline* works but says nothing about *detection*. NetGuard breaks that loop:

- Those four rules are quarantined in **`demo.rules`** and **never counted as detection** — they only prove the capture→alert pipeline is alive.
- Real coverage comes from **Emerging Threats Open**, measured against a catalogue of techniques the project does *not* control.
- The two author-written rules match **generalizable** attack traits (a legacy-`MSIE 6.0` beacon user-agent at a check-in rate; a ≥1 MB outbound POST), never the simulator's own paths — so they would fire on traffic the sim never sent.
- Every claim traces to a scored run at a named ruleset version, and CI fails any change that regresses it.

## Architecture

```
        ┌──────────────── netguard-lab (10.10.0.0/24) ────────────────┐
        │                                                              │
  ┌───────────┐     ┌──────────────┐          ┌──────────────────┐    │
  │ traffic-  │────▶│ monitored-   │◀─────────│   attack-sim     │    │
  │ generator │     │ app (nginx)  │          │ (profile: attack)│    │
  └───────────┘     └──────┬───────┘          └──────────────────┘    │
                           │ shared network namespace                  │
                    ┌──────┴───────┐                                   │
                    │  Suricata 7  │  ET Open + local.rules + demo.rules│
                    │  eve.json    │                                   │
                    └──────┬───────┘                                   │
        └──────────────────┼───────────────────────────────────────────┘
                           │ eve.json (volume)
        ┌──────────────────┼──────── netguard-monitor ─────────────────┐
        │  Promtail ─▶ Loki ─▶ Grafana ◀─ Prometheus (◀ cAdvisor, opt) │
        └──────────────────────────────────────────────────────────────┘
```

Suricata runs in **`monitored-app`'s network namespace** (`network_mode: service:monitored-app`) and inspects its `eth0`, so it sees exactly the traffic reaching the protected asset — portably on Linux, Windows, and macOS. (Host-mode capture saw nothing usable on Windows/macOS; see [ADR-001](docs/adr/README.md).) `HOME_NET` is scoped to the monitored app, so the in-lab attacker is `EXTERNAL_NET` and ET Open's `$EXTERNAL_NET → $HTTP_SERVERS` rules fire against it.

Three segmented networks isolate the planes: `netguard-lab` (attacker-controlled data plane), `netguard-monitor` (observability), `netguard-mgmt` (operator ingress). The attack simulator is attached only to `netguard-lab` and can never reach the monitoring plane.

## Quick start — clone, run, read the score in ~10 minutes

Requires Docker Engine with Compose v2 (a Linux host or Docker Desktop). Python is optional — the scorer falls back to a container.

```sh
cp .env.example .env          # then edit GRAFANA_ADMIN_PASSWORD

# 1. Bring up the lab plane (fetches + pins ET Open, starts namespace capture)
docker compose up -d --build suricata traffic-generator

# 2. Launch the attack catalogue and score it against the committed baseline
SCENARIO=all ./scripts/run-catalogue.sh
#    → runs/<ts>/{manifest.json, eve.json, scorecard.json} + a printed table
```

The everyday `docker compose up` stays **benign**: the attack simulator is profile-gated (`profiles: [attack]`) and only runs when you invoke the catalogue.

Verify the scorer logic with no stack running (pure-function self-test over committed fixtures):

```sh
python -m unittest tests.test_scorer -v     # or: docker run --rm -v "$PWD":/w -w /w python:3.12-alpine python -m unittest tests.test_scorer
```

## How detection is measured

**Three rule layers** (`services/suricata/rules/`):

| Layer | Source | Role |
|---|---|---|
| ET Open (`suricata.rules`) | Emerging Threats Open, fetched + content-pinned by `scripts/update-rules.sh` | Broad, real-world coverage |
| `local.rules` | Two author rules (A09 beacon, A10 exfil) | Close measured gaps ET Open missed |
| `demo.rules` | The four self-referential rules | Pipeline liveness only — **never** scored ([ADR-003](docs/adr/README.md)) |

**The catalogue** (`services/attack-sim/`) launches 10 attack techniques + 4 negative controls, and writes a self-describing `manifest.json` recording each technique's real time window, ATT&CK mapping, and expected signature class. That table *is* the test spec.

**The scorer** (`netguard/scorer.py`) joins the manifest against `eve.json` — matching on time window **and** source IP, so the always-on traffic generator is never miscredited — and computes recall / precision / FP / MTTD. Two guards keep it honest:

- Demo sids `1000001–1000004` are excluded from detection but used as **liveness proof**.
- A dead capture is reported as **`INVALID_RUN`**, never a misleading `0/10` — a broken pipeline and a ruleset that misses everything must not look identical.

**The baseline gate** — `eval/baseline.json` records the committed level (recall 0.9, FP 0). The scorer fails a run that drops below it. An intentional improvement bumps the baseline *in the same commit*, so every metric move is a reviewable diff — never silent drift.

## CI / DevSecOps

`.github/workflows/ci.yml` — all green, including the detection gate run on a hosted runner:

| Job | Gate |
|---|---|
| validate | `docker compose config`, ruff, yamllint, shellcheck, + gitignore & demo-rules guards |
| secrets | gitleaks over full history |
| unit | scorer self-test |
| rules | `suricata -T` compiles local + demo rules |
| sast | Semgrep (no ERROR severity) |
| containers | Trivy filesystem scan (no CRITICAL) |
| detection | brings the stack up, runs the catalogue, **fails if recall < or FP > baseline** |

Local mirror of the git-hygiene gates: `pipx install pre-commit && pre-commit install`.

## Stated limitations

Credibility comes from naming these, not hiding them:

- **The catalogue is a fixed, known set; real attackers improvise.** Recall against the catalogue is an upper bound on real-world recall, not an estimate of it.
- **Namespace-shared capture scopes Suricata to the monitored app.** Traffic that never reaches it — e.g. A08's DNS tunneling to the resolver — is out of view by design ([ADR-001](docs/adr/README.md)). Multi-target capture returns as a documented option for a Linux-host deployment.
- **ET Open is a subset of ET Pro**; some techniques it misses would be caught by paid rules. The scorecard reports which.
- **The lab is a single-target environment**, so base rates and traffic mix don't match production — precision here is optimistic.
- **ET Open is a rolling ruleset.** The CI detection gate re-fetches it, so a future ET change that drops coverage will (correctly) fail the gate until investigated or the baseline is re-pinned. It is not hermetic.

## Security posture

The two-sided threat model is in [`architecture/threat-model.md`](architecture/threat-model.md): Adversary A (what NetGuard must detect, ATT&CK-mapped) and Adversary B (attacks against NetGuard itself). Decisions and their trade-offs are recorded as [ADRs](docs/adr/README.md).

Secrets stay out of git (`.env` ignored, gitleaks in CI and pre-commit, history verified clean). WireGuard keys live in a Docker volume, never the tree.

**Known hardening gaps (tracked, not yet closed):** Prometheus/Grafana are still published on `0.0.0.0` and the WireGuard image is unpinned — these are the remaining M1 items (loopback binds + digest pin) and must be closed before any non-local deployment.

## Repository layout

```
docker-compose.yml            # the stack; suricata shares monitored-app's netns
services/
  suricata/                   # suricata.yaml + rules/{local,demo}.rules
  attack-sim/                 # catalogue.py + run_catalogue.py (profile: attack)
  traffic-generator/          # benign liveness traffic
netguard/scorer.py            # manifest × eve.json → scorecard
eval/                         # baseline.json (gate) + ruleset.lock (ET Open pin)
scripts/                      # run-catalogue, update-rules, guards, ci-detection
monitoring/                   # loki / promtail / prometheus / grafana provisioning
tests/                        # scorer self-test + fixtures
docs/                         # ENGINEERING_PLAN.md, DEMO.md, adr/
architecture/                 # threat-model, data-flow, diagram
.github/workflows/ci.yml      # the pipeline
```

## Status & roadmap

Shipped and CI-verified: version control, namespace-shared capture, the scorer + catalogue, ET Open + author rules (**9/10**), and the CI regression gate. A live walkthrough is scripted in [`docs/DEMO.md`](docs/DEMO.md).

Next: close the remaining M1 hardening (loopback binds, WireGuard digest pin); then the deferred phases from the 2.0 proposal (response engine, AI incident analyst, Terraform/K3s) — now sitting on a foundation where detection is a measured number rather than a claim.

The full design rationale is in [`docs/ENGINEERING_PLAN.md`](docs/ENGINEERING_PLAN.md).

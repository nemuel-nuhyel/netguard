# NetGuard 2.1 — Engineering Plan

**From a network-security lab to a security-monitoring platform whose detection is *measured*, not asserted.**

| | |
|---|---|
| **Status** | Design complete; builds on the shipped Sprint 1 |
| **Supersedes** | NetGuard 2.0 Proposal (roadmap only) — this plan makes it buildable and adds the missing evidence layer |
| **Stack (kept)** | Docker Compose · WireGuard · Suricata 7 · Loki · Promtail · Prometheus · Grafana |
| **Stack (added)** | Emerging Threats Open ruleset · attack-simulation harness · MITRE ATT&CK-mapped catalogue · GitHub Actions CI · detection scorecard |
| **Audience** | Hiring managers / security engineers reviewing a portfolio repo |

---

## 0. What this document is

Sprint 1 already exists and is better than most portfolio labs: healthchecks on every service, three segmented Docker networks, pinned image digests, no secrets in the tree, and a threat model that actually enumerates assets. The NetGuard 2.0 proposal laid out an ambitious five-phase roadmap.

Neither document addresses the two things a reviewer notices first. This plan does, in order of how much they cost the project:

1. **The work is not in version control.** The GitHub repository contains four tracked files; the compose stack, every service, every monitoring config, and the architecture docs are untracked. The project effectively does not exist to anyone who cannot see the author's Desktop.
2. **The IDS only detects its own traffic.** All four Suricata rules match strings the project's own traffic generator emits. The dashboards light up, but the detection rate against anything an attacker would actually do is unknown — and unmeasured.

Everything else here is downstream of fixing those two. §1 is the audit, §2–3 rebuild the threat model and correct the architecture, §4 is the detection-credibility engine (the core contribution), §5 is the measurement methodology, §6–7 cover hardening and delivery.

---

## 1. Audit of the shipped Sprint 1

### 1.1 What is already right — and stays

These are not filler. A reviewer credits them, and the plan preserves every one.

| Strength | Evidence |
|---|---|
| Healthchecks on every service | All 8 services define `healthcheck` with sensible `start_period` |
| Real network segmentation | `netguard-mgmt` / `netguard-lab` / `netguard-monitor` on distinct subnets, services pinned to static IPs |
| Least-exposure port mapping | Only Grafana, Prometheus, WireGuard published; Loki, Promtail, cAdvisor internal |
| Reproducible image pins | Every image except one is pinned to a specific tag |
| Secrets kept out of git | `.env` untracked and git-ignored; verified — the secret is not in history |
| A threat model exists at all | `architecture/threat-model.md` enumerates assets, risks, controls, assumptions |
| Safe-by-default posture | No firewall automation in Sprint 1; response deferred until observability is proven — exactly the right sequencing |

### 1.2 Findings, by severity

**🔴 F1 — The repository does not contain the project.**

```
$ git ls-files
.gitignore
README.md
docker/wireguard/config
docker/wireguard/docker
```

Three commits exist; two are titled "progress report." The progress is on disk but not committed. Consequences: no history, no backup, nothing for a reviewer to read, and a single disk failure from total loss. This is finding number one because every other improvement is invisible until it is fixed.

**🔴 F2 — `.gitignore` is a landmine under the files the roadmap adds next.**

```gitignore
*.conf
**/config/*
```

Verified against the current tree: these do **not** hide today's files — `git add -A` stages `suricata.yaml`, every `*-config.yml`, and the compose file correctly, and the only ignored secret is `.env` (correct). So this is not swallowing the *current* work. But it is a trap for exactly the files the 2.0 repo structure introduces next: `services/wireguard/config/wg0.conf`, per-service `config/` directories, and any `entrypoint`-adjacent `.conf`. The moment those are added, they vanish silently — committed clean, files appear, pieces missing, no error. It is severity-🔴 because it detonates precisely when the project grows, and the fix costs one file. Narrow to specific secret names/paths (`wg0.conf`, `peer*/`, `*.key`, `*_privatekey`, the linuxserver wireguard config dir) before the next feature lands. (§3.4)

**🔴 F3 — The IDS detects only itself.**

| Rule (sid) | Matches | Source of that traffic |
|---|---|---|
| 1000001 | `content:"NetGuardTrafficGenerator"` | The generator's own `User-Agent` |
| 1000002 | `http.uri "/admin"` | `generator.py` → `fetch("/admin/netguard-lab")` |
| 1000003 | `dns.query "example.com"` | `DNS_PROBE_HOST=example.com` |
| 1000004 | `tcp any -> any 8080` | `PORT_PROBE_PORTS="80,8080"` |

Every signature matches traffic the project generates for itself. The loop is closed: generator → rule → dashboard → generator. This demonstrates that the *pipeline* works (traffic in, alert out, panel lit) but says nothing about *detection* — whether Suricata would catch a port scan, a SQL-injection attempt, or C2 beaconing. It is the same failure mode as a phishing scanner with hand-invented weights: the system asserts it detects things instead of measuring whether it does. §4 replaces this with a measured harness. (This is the single highest-value change in the plan.)

**🔴 F4 — Suricata sees no traffic on the author's actual host.**

`network_mode: host` + `-i any` does not capture Docker bridge traffic on Windows or macOS; the "host" is the Linux VM backing Docker Desktop, not the bridge where the lab containers talk. The author is on Windows. So on the development machine, Suricata is running and healthy and inspecting nothing. The README hand-waves this as a "platform limitation." It is fixable, not inherent. (§3.2)

**🟡 F5 — Prometheus and Grafana are published on all interfaces with weak/no auth.**

`ports: "9090:9090"` and `"3000:3000"` bind `0.0.0.0`. Prometheus has no authentication whatsoever; anyone on the same LAN (university, café, shared flat) can read every metric and query the admin API. Grafana ships a default-password path. Bind both to `127.0.0.1`. (§3.3)

**🟡 F6 — One unpinned image, and it is the most privileged one.**

`lscr.io/linuxserver/wireguard:latest` is the only floating tag, and it is the container running with `NET_ADMIN` + `SYS_MODULE`. A `latest` that moves under a capability that can reconfigure the host network stack is exactly the wrong place to accept supply-chain drift. Pin to a digest. (§3.3)

**🟡 F7 — The security success metric is unenforced, and points at the wrong platform.**

The proposal's success table lists "Secret leakage: 0, measured by `gitleaks detect` on every commit." There is no CI and no pre-commit hook, so nothing measures it. The proposal also specifies **GitLab** CI while the repo lives on **GitHub**. Pick GitHub Actions (where the code is) and make the metric real. (§6)

**🟢 F8 — `cadvisor: privileged: true` + `/:/rootfs:ro` is host-root-equivalent.**

Correctly gated behind a Compose profile, so it is opt-in — good. But mounting the host root filesystem and running privileged belongs in the threat model as an *accepted, isolated risk with a stated blast radius*, not merely listed as an "asset exposed to cAdvisor." (§2)

**🟢 F9 — Suricata `checksum-validation: no` + `community-id` seed 0.**

Minor, but `checksum-validation: no` can mask genuinely malformed packets in some capture setups, and it is worth a one-line justification (offloaded checksums in virtualized NICs) rather than leaving a reviewer to wonder. Non-blocking.

**🟢 F10 — Traffic generator has no negative controls.**

`generator.py` emits only benign traffic that the rules are written to match. There is no benign traffic that *resembles* an attack but should **not** alert — the false-positive surface is untested. The §4 harness introduces exactly these near-miss cases. (§5)

### 1.3 The through-line

F3 and F10 are the same problem F4 in EmailGuard was: **the system reports success against inputs chosen to make it succeed.** F1 and F2 are the same problem in a different dimension — the evidence of the work not being durably captured. The rest of this plan is organized around turning assertion into measurement, and around making the result something a reviewer can clone and reproduce.

---

## 2. Threat model (rebuilt, two-sided)

Sprint 1's threat model covers one direction: protecting the lab's own assets (keys, credentials, exposed ports). A monitoring platform needs the second direction too — the model of *what it is supposed to detect*, and what it cannot. Without that second half, "detection rate" has no denominator.

### 2.1 Adversary A — the intruder on the lab network (what NetGuard must detect)

The threat NetGuard exists to observe. Modeled against MITRE ATT&CK tactics so the detection catalogue in §4.2 has a spine.

| ATT&CK tactic | Concrete lab behaviour | Detectable by |
|---|---|---|
| Reconnaissance | Port/host scan of the lab subnet (`nmap -sS`, `-sV`) | ET scan rules; anomalous SYN fan-out |
| Initial Access | Path/vhost enumeration, exposed-admin probing (`gobuster`, Nikto) | ET WEB_SERVER rules; URI heuristics |
| Execution / Exploit | SQLi, XSS, command-injection against the nginx target | ET WEB_SPECIFIC / SQL rules |
| Credential Access | HTTP basic-auth / login brute force (`hydra`-style) | ET brute-force + rate heuristics |
| Command & Control | Beaconing to an external listener, DNS tunneling | ET MALWARE / DNS rules; periodicity heuristics |
| Exfiltration | Large or odd-protocol outbound transfer | ET exfil rules; flow-volume anomaly |

### 2.2 Adversary B — attacking NetGuard itself (what it must survive)

Every input the platform ingests is attacker-influenced: packets are attacker-authored by definition, and Suricata parses them. This half was absent from Sprint 1.

| Threat | Vector | Control |
|---|---|---|
| Evasion | Fragmentation, overlapping segments, obfuscated payloads bypass a signature | Stream reassembly tuned; measured evasion cases in §4; ET normalization rules |
| Alert flooding | Attacker triggers thousands of low-value alerts to bury a real one | Severity-tiered dashboards; alert-rate panels; the scorecard tracks precision, not just recall |
| Log-pipeline DoS | High-volume `eve.json` fills the disk or overruns Loki | Loki retention + rate limits; disk-usage alert; Suricata `eve.json` size cap |
| Prometheus/Grafana exposure | Unauthenticated `0.0.0.0` binds (F5) | Loopback binds; auth on Grafana; documented as a hard requirement before any non-local deploy |
| Privileged-container escape | cAdvisor `privileged` + host-root mount (F8) | Profile-gated (opt-in), read-only mounts, documented blast radius, never on by default |
| Supply-chain drift | `wireguard:latest` under `NET_ADMIN`+`SYS_MODULE` (F6) | Digest pinning; Trivy image scan in CI |
| Secret leakage | Keys or `.env` committed | Narrowed `.gitignore` (F2); gitleaks in CI *and* pre-commit; history scan before first push |

### 2.3 Trust boundaries and invariants

```
   EXTERNAL_NET  ─┬─  WireGuard gateway (NET_ADMIN, SYS_MODULE)  ── highest privilege
                  │
   netguard-lab  ─┼─  monitored-app · traffic-gen · attack-sim   ── attacker-controlled data plane
                  │        │
                  │        └── Suricata (namespace-shared, NET_RAW) ── observes the data plane
                  │
   netguard-monitor ─┴─ Loki · Promtail · Prometheus · Grafana   ── control plane, loopback-only ingress
```

Invariants, each with a test that fails loudly if broken:

1. No monitoring service (Loki, Prometheus, Grafana, cAdvisor) is reachable from a non-loopback interface by default.
2. The attack-simulation container can reach only `netguard-lab`, never `netguard-monitor`.
3. No image runs on a floating tag.
4. No secret is present in the tracked tree or in git history.
5. Every detection claim in the README traces to a scored run of the §4 harness at a named ruleset version.
---

## 3. Architecture corrections

The topology is sound; three mechanisms are wrong and one is missing. Each fix is small and each closes a specific finding.

### 3.1 What stays

Three segmented networks, static IPs, healthchecks, the Loki/Promtail/Prometheus/Grafana observability spine, and the safe-by-default no-automation stance. None of that changes.

### 3.2 Suricata capture that works on the author's machine (F4)

`network_mode: host` inspects the Docker Desktop backing VM, not the lab bridge — so on Windows/macOS it sees nothing relevant. Replace it with **namespace sharing**, the standard sidecar-IDS pattern:

```yaml
suricata:
  image: jasonish/suricata:7.0.7          # pinned, not :7
  network_mode: "service:monitored-app"    # share the target's netns
  cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]
  command: ["-i", "eth0", ...]             # the app's interface, portable
  depends_on:
    monitored-app:
      condition: service_healthy
```

Suricata now lives inside `monitored-app`'s network namespace and sees exactly the traffic reaching the target — including the attack simulator's — on Linux, Windows, and macOS identically. This is also a cleaner demo story than "host mode, but only really on Linux": the IDS watches the asset it is protecting, which is what a reviewer expects to see.

A short ADR records the trade-off: namespace sharing scopes Suricata to one target's traffic rather than the whole host, which is precisely the right scope for a lab whose monitored asset is that one target. Multi-target capture returns as a documented option for a Linux-host deployment.

### 3.3 Exposure and pinning (F5, F6)

```yaml
prometheus:
  ports: ["127.0.0.1:9090:9090"]     # was 0.0.0.0
grafana:
  ports: ["127.0.0.1:3000:3000"]     # was 0.0.0.0
  environment:
    GF_SECURITY_ADMIN_PASSWORD__FILE: /run/secrets/grafana_admin   # Docker secret, not env
wireguard:
  image: lscr.io/linuxserver/wireguard@sha256:<digest>             # was :latest
```

Loopback binds make the services reachable through the WireGuard tunnel or an SSH forward — which is the point of having a VPN in the project — without publishing them to whatever LAN the laptop is on. Grafana's admin password moves from an environment variable (visible in `docker inspect` and process listings) to a Docker secret.

### 3.4 The `.gitignore` rewrite (F2)

```gitignore
# Secrets — specific, not blanket
.env
*.key
*_privatekey
*privatekey*
wg0.conf
**/wireguard/config/**       # linuxserver wireguard writes keys here
peer*/                       # generated peer dirs

# Runtime data
loki-data/
prometheus-data/
grafana-data/
*.log
*.pid

# NOT ignored (previously swallowed): suricata.yaml, *-config.yml,
# datasources.yml, dashboards.yml, docker-compose.yml, all of monitoring/
```

The principle: ignore secrets by their specific names and locations, never by a wildcard broad enough to hide the project. A `check-gitignore` CI step asserts that the known config files are *not* ignored, so this failure cannot silently return.

### 3.5 New service — the attack simulator

The missing component. A container on `netguard-lab` only (invariant 2), running a catalogue of recognizable, benign-to-the-host attack patterns against `monitored-app`:

```yaml
attack-sim:
  build: ./services/attack-sim
  networks: [netguard-lab]           # cannot reach netguard-monitor
  profiles: [attack]                 # opt-in; never runs in the default demo
  environment:
    TARGET: http://10.10.0.20
    SCENARIO: ${SCENARIO:-all}
    MODE: ${MODE:-catalogue}         # catalogue = labeled run for scoring
```

It is profile-gated so the everyday `docker compose up` stays benign, and it emits a **labeled manifest** of every attack it launched (timestamp, technique, ATT&CK ID, expected signature class) — which is what turns a demo into a measurement in §5. Tooling is standard and installable: `nmap`, `nikto`, a small Python SQLi/XSS/dir-enum driver, and a DNS-tunneling/beacon simulator. Nothing is a real exploit; the nginx target is unmodified and the payloads are detection triggers, not intrusions.

### 3.6 Corrected topology

```
        ┌────────────── netguard-lab (10.10.0.0/24) ──────────────┐
        │                                                          │
  ┌───────────┐     ┌──────────────┐        ┌──────────────────┐  │
  │ traffic-  │────▶│ monitored-   │◀───────│   attack-sim     │  │
  │ generator │     │ app (nginx)  │        │ (profile: attack)│  │
  └───────────┘     └──────┬───────┘        └──────────────────┘  │
                           │ shared netns                          │
                    ┌──────┴───────┐                               │
                    │  Suricata 7  │  ET Open + local.rules        │
                    │  eve.json    │                               │
                    └──────┬───────┘                               │
        └──────────────────┼──────────────────────────────────────┘
                           │ eve.json (volume)
        ┌──────────────────┼──── netguard-monitor (loopback ingress) ┐
        │           ┌──────┴─────┐   ┌───────────┐   ┌────────────┐  │
        │ Promtail ▶│    Loki    │──▶│  Grafana  │◀──│ Prometheus │  │
        │           └────────────┘   │ dashboards│   │ (cAdvisor) │  │
        │                            │ + SCORECARD│  └────────────┘  │
        └────────────────────────────┴───────────┴──────────────────┘
                                          ▲
                              ┌───────────┴────────────┐
                              │  detection scorecard   │  ← §5, the new panel
                              │  recall · precision    │
                              │  per ATT&CK technique  │
                              └────────────────────────┘
```

---

## 4. Detection credibility — the core contribution

This is what separates NetGuard 2.1 from Sprint 1 and from most portfolio labs. The claim "NetGuard detects network attacks" becomes a number, produced by a repeatable run, displayed on a dashboard, and regression-gated in CI.

### 4.1 Three rule layers, not one

| Layer | Source | Role |
|---|---|---|
| **Community coverage** | Emerging Threats **Open** ruleset (free, `suricata-update`'s default source, current for Suricata 7) | Broad, real-world signatures for scans, web attacks, malware, exfil — the coverage a hand-written `local.rules` can never match |
| **Lab-specific** | Curated `local.rules`, rewritten | Signatures for the specific monitored-app and lab topology, *not* for the project's own generator |
| **Author-authored detection** | A handful of new rules written to catch specific catalogue techniques ET misses | The part that demonstrates the author can write detection, measured by whether it actually fires |

ET Open is managed with `suricata-update`, pinned to a ruleset version so a scored run is reproducible. The existing four self-referential rules are demoted to a `demo.rules` file used only for the benign pipeline smoke test — kept, clearly labeled as pipeline-validation-only, never counted as detection.

### 4.2 The attack catalogue

Each entry is a technique, its ATT&CK mapping, the tool that produces it, and the signature class expected to fire. This table *is* the test spec.

| ID | Technique | ATT&CK | Simulated by | Expected detection |
|---|---|---|---|---|
| A01 | SYN port scan | T1046 | `nmap -sS` | ET SCAN + SYN fan-out |
| A02 | Service/version scan | T1046 | `nmap -sV` | ET SCAN |
| A03 | Directory enumeration | T1083/T1595 | `gobuster`/Nikto | ET WEB_SERVER |
| A04 | SQL injection | T1190 | Python driver | ET WEB_SPECIFIC_APPS / SQL |
| A05 | Reflected XSS | T1059 | Python driver | ET WEB_SERVER XSS |
| A06 | Command injection attempt | T1190 | Python driver | ET WEB_SPECIFIC |
| A07 | HTTP auth brute force | T1110 | scripted | ET brute-force / rate |
| A08 | DNS tunneling | T1071.004 | tunneler sim | ET DNS + query-length heuristic |
| A09 | C2 beaconing (periodic) | T1071/T1571 | beacon sim | ET MALWARE + periodicity |
| A10 | Suspicious outbound volume | T1048 | bulk transfer | ET exfil / flow-volume |

Plus **negative controls** — traffic that resembles an attack but is legitimate, to measure false positives (F10):

| ID | Benign-but-suspicious | Must NOT alert as attack |
|---|---|---|
| N01 | Legitimate admin login to the app | Not brute force |
| N02 | Large legitimate file download | Not exfil |
| N03 | Rapid but normal API polling | Not a scan |
| N04 | DNS lookups for many distinct real hosts | Not tunneling |

### 4.3 The scorecard

A run of `MODE=catalogue` produces a labeled manifest of launched techniques; the scorer joins it against Suricata's `eve.json` alerts on time window and community-id, and computes:

```
Per technique:  detected? (≥1 alert of the expected class within the window)
Aggregate:      recall    = techniques detected / techniques launched
                precision = true-positive alerts / all alerts
                FP count  = alerts fired during negative-control windows
                MTTD      = median seconds from launch to first alert
```

Reported as a table and rendered as a Grafana panel. The honest headline number is **recall at a fixed false-positive count**, not raw alert volume — the same discipline as a detector's false-positive budget. A run that lights up 5,000 alerts and misses the SQLi is worse than one that fires 12 and catches everything, and the scorecard is built to make that visible rather than hide it.

### 4.4 Why this is the credible core

A reviewer reading `local.rules` next to `generator.py` sees the closed loop in seconds. A reviewer reading a scorecard that says *"detected 9/10 catalogue techniques, missed A08 DNS-tunneling, 2 false positives on N04, MTTD 3.2s, ET Open ruleset 2026-xx-xx"* sees an engineer who measured their own system and reported the miss. The missed technique is not a flaw to hide — it is the most credible line in the repository, because it proves the number is real.

---

## 5. Measurement methodology

### 5.1 Build the scorer before broadening the rules

The mistake to avoid is the Sprint 1 mistake in a new form: adding ET Open, watching alerts appear, and declaring success. Without the scorer there is still no denominator. So the scorer and the catalogue come **first**, run against the *current* four-rule setup to produce an intentionally dismal baseline (detects ~0/10 real techniques), and every rule change afterward is measured as a delta against it.

### 5.2 The run

```
docker compose --profile attack run attack-sim   # MODE=catalogue, emits manifest.json
python -m netguard.scorer \
    --manifest runs/<ts>/manifest.json \
    --eve      /var/log/suricata/eve.json \
    --ruleset-version "$(suricata-update --version-string)" \
    --baseline eval/baseline.json
```

Output: `runs/<ts>/scorecard.json` + a human-readable table. The ruleset version and Suricata version are stamped into every scorecard so a result is reproducible.

### 5.3 CI regression gate

A GitHub Actions job spins the stack up on an ephemeral runner, runs the catalogue, and fails the PR if:

- catalogue recall drops below the committed baseline,
- the negative-control false-positive count rises,
- any `demo.rules` signature is counted as real detection (guard against the closed loop returning),
- `docker compose config` fails, or gitleaks finds a secret.

An intentional detection improvement updates `eval/baseline.json` in the same commit, so the metric change is a visible, reviewable diff — never silent drift.

### 5.4 Stated limitations (in the README)

Credibility comes from naming these, not hiding them:

- The catalogue is a fixed, known set; real attackers improvise. Recall against the catalogue is an upper bound on real-world recall, not an estimate of it.
- ET Open is a subset of ET Pro; some techniques it misses would be caught by paid rules. The scorecard reports which.
- Namespace-shared capture scopes Suricata to the monitored app; lateral movement between other lab hosts is out of view by design (§3.2).
- The lab is a single-target environment; base rates and traffic mix do not match a production network, so precision is optimistic.

---

## 6. Hardening and DevSecOps (F7)

Platform: **GitHub Actions**, because that is where the code is. The NetGuard 2.0 proposal's GitLab pipeline is retargeted, not discarded.

| Stage | Tools | Gate |
|---|---|---|
| validate | `docker compose config`, `yamllint`, `ruff`, `shellcheck` | syntax/lint clean |
| secrets | **gitleaks** (CI **and** pre-commit hook) | zero findings — makes success-metric #5 real |
| SAST | Semgrep | no high-severity |
| containers | Trivy (image + filesystem) | no critical CVE on pinned images; catches F6 drift |
| rules | `suricata -T` on merged ruleset | rules compile |
| detection | the §5 catalogue run + scorecard | recall ≥ baseline, FP ≤ baseline |
| build | compose build all services | green |

Pre-commit hooks (`gitleaks`, `ruff`, `shellcheck`, `check-gitignore`) stop the two 🔴 git findings from ever recurring.

---

## 7. Delivery plan

Ordered by risk retired. The two 🔴 git findings are fixed in the first hours, because nothing else is visible until they are — and because they are the cheapest, highest-leverage changes in the entire plan.

### M0 · Day 1 · Make the work exist (~3 h)
Narrow `.gitignore` (F2); scan the working tree and full history with gitleaks; stage and commit the untracked project in coherent commits; confirm the remote reflects reality. **Exit:** `git ls-files` lists the whole project; gitleaks clean on history. **Artifact:** a repo a stranger can clone and run.

### M1 · Days 2–3 · Fix capture and exposure (~4 h)
Namespace-shared Suricata (F4); loopback binds + Grafana secret (F5); pin WireGuard by digest (F6). **Exit:** on the author's Windows machine, generated traffic appears in `eve.json`; Prometheus/Grafana unreachable from another LAN host. **Artifact:** before/after `eve.json` capture proof.

### M2 · Days 4–5 · Scorer + catalogue skeleton (~6 h)
Attack-sim container, labeled manifest, the scorer, `eval/baseline.json` against the current four rules (the deliberately dismal baseline). **Exit:** `scorer` produces a scorecard showing ~0/10 real recall. **Artifact:** the baseline scorecard, committed.

### M3 · Week 2 · ET Open + real detection (~10 h)
Integrate ET Open via `suricata-update`, pin the ruleset version, demote the self-referential rules to `demo.rules`, author a few gap-filling rules, iterate against the scorecard. **Exit:** recall ≥ 8/10 with a documented miss and a bounded FP count. **Artifact:** the scorecard with the honest miss called out; a Grafana scorecard panel.

### M4 · Week 2–3 · CI/CD (~8 h)
GitHub Actions with every stage in §6, including the catalogue run on an ephemeral runner; pre-commit hooks; MR template. **Exit:** a PR that regresses detection or leaks a secret fails automatically. **Artifact:** a screenshot of the gate catching a deliberately broken rule.

### M5 · Week 3 · Docs and story (~5 h)
Rewrite the README around the scorecard; update the threat model to the two-sided version; ADRs; a 3-minute demo showing an attack launched and detected live. **Exit:** a reviewer can clone, run the catalogue, and read the score in 10 minutes. **Artifact:** the demo recording.

Later phases from the 2.0 proposal (Python response engine, AI incident analyst, Terraform/K3s) remain valid and now sit on top of a measured foundation — they are strictly better once detection is a number rather than a claim. They are explicitly out of scope for 2.1.

### If time is short
M0 and M1 are non-negotiable — they fix the two findings a reviewer sees first. M2+M3 are the contribution. M4 is what makes it look senior. M5 is what makes it legible. Cut from the bottom: even M0–M3 alone turns "a lab that detects itself, uncommitted" into "a version-controlled IDS platform with a measured 8/10 detection rate," which is a categorically different portfolio entry.

---

## 8. Architecture decision records

| ADR | Decision | Rationale |
|---|---|---|
| 001 | Namespace-shared Suricata over host-mode | Host mode captures nothing on the author's Windows host (F4); sharing the target netns is portable and scopes the IDS to the asset it protects |
| 002 | ET Open ruleset alongside `local.rules` | A hand-written rule file cannot approach real-world coverage; ET Open is free, standard, and `suricata-update`-managed |
| 003 | Self-referential rules demoted to `demo.rules`, never scored | They validate the pipeline, not detection; counting them is the closed loop that made Sprint 1's claim hollow (F3) |
| 004 | Scorer built before rules are broadened | Without a denominator, "more alerts" is not "better detection" — the Sprint 1 mistake in a new form |
| 005 | Recall at a fixed false-positive count as the headline metric | Alert volume rewards noise; a personal SOC that cries wolf gets muted. Precision is a first-class number |
| 006 | `.gitignore` by specific secret names, never `*.conf`/`config/*` | Blanket ignores silently swallow a config-centric project (F2); a CI check asserts key files stay tracked |
| 007 | GitHub Actions, not GitLab CI | The code is on GitHub; the proposal's GitLab choice mismatched the repo (F7) |
| 008 | Loopback binds for Prometheus/Grafana | Reachable via the VPN/SSH the project already has; never published to an untrusted LAN (F5) |
| 009 | Attack-sim profile-gated and lab-network-only | The default demo stays benign; the simulator can never reach the monitoring plane (invariant 2) |

---

## Appendix A — Findings-to-fix traceability

| Finding | Severity | Fixed in |
|---|---|---|
| F1 work not in version control | 🔴 | M0 |
| F2 `.gitignore` swallows the project | 🔴 | M0, §3.4, ADR-006 |
| F3 IDS detects only itself | 🔴 | M2–M3, §4, ADR-003 |
| F4 no capture on author's host | 🔴 | M1, §3.2, ADR-001 |
| F5 unauth'd `0.0.0.0` binds | 🟡 | M1, §3.3, ADR-008 |
| F6 `wireguard:latest` under high privilege | 🟡 | M1, §3.3 |
| F7 unenforced security metric, wrong CI platform | 🟡 | M4, §6, ADR-007 |
| F8 cadvisor privileged host-root | 🟢 | §2.2 (documented risk) |
| F9 checksum-validation off | 🟢 | §3 note |
| F10 no false-positive controls | 🟢 | §4.2 negative controls, ADR-005 |

## Appendix B — References

- [Suricata rule management with suricata-update (ET Open is the default source)](https://docs.suricata.io/en/latest/rule-management/suricata-update.html)
- [Emerging Threats Open ruleset for Suricata 7 (community announcement)](https://forum.suricata.io/t/emerging-threats-pro-open-ruleset-for-suricata-7-0-3-now-available/4714)
- [ET Open rules download index](https://rules.emergingthreats.net/open/suricata/rules/)
- [MITRE ATT&CK — Enterprise tactics and techniques](https://attack.mitre.org/)

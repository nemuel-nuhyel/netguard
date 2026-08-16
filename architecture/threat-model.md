# NetGuard Threat Model

A monitoring platform has two threat directions, and Sprint 1 only modeled one. This model covers both: **what NetGuard must detect** (Adversary A) and **what NetGuard must survive** (Adversary B). Without the first, "detection rate" has no denominator; without the second, the platform is an unguarded attack surface that happens to parse hostile packets.

## Assets

- WireGuard private keys and generated peer configuration (in a Docker volume, never the tree).
- Suricata `eve.json` security events — the evidence the whole platform produces.
- The detection scorecard and its baseline (`eval/baseline.json`) — the integrity of the *measurement*.
- Grafana dashboards and admin credentials; Loki/Prometheus runtime data.
- Host cgroups and container metadata exposed to cAdvisor (opt-in, profile-gated).

---

## Adversary A — the intruder on the lab network (what NetGuard must detect)

The threat NetGuard exists to observe, modeled against MITRE ATT&CK so the detection catalogue has a spine. Each row maps to a catalogue entry (`services/attack-sim/catalogue.py`) that is *measured*, not assumed.

| ATT&CK tactic | Lab behaviour | Catalogue | Detected by | Result |
|---|---|---|---|---|
| Reconnaissance | Port / service scan (`nmap -sS`, `-sV`) | A01, A02 | ET SCAN | ✅ |
| Initial Access | Path / vhost enumeration | A03 | ET WEB_SERVER | ✅ |
| Execution / Exploit | SQLi, XSS, command injection | A04–A06 | ET WEB_SPECIFIC / WEB_SERVER | ✅ |
| Credential Access | HTTP auth brute force | A07 | ET SCAN brute-force | ✅ |
| Command & Control | DNS tunneling; periodic beaconing | A08, A09 | ET DNS; author beacon rule | A08 ✗ (scope), A09 ✅ |
| Exfiltration | Large / odd outbound transfer | A10 | Author exfil rule | ✅ |

Plus **negative controls** (N01–N04): benign traffic that *resembles* an attack (a legitimate admin login, a large download, rapid API polling, many distinct DNS lookups) and must **not** alert. These measure the false-positive surface — currently **0 FP**.

---

## Adversary B — attacking NetGuard itself (what it must survive)

Every input the platform ingests is attacker-influenced: packets are attacker-authored by definition, and Suricata parses them.

| Threat | Vector | Control | Status |
|---|---|---|---|
| Evasion | Fragmentation / obfuscation bypasses a signature | Stream reassembly tuned; ET normalization; measured via the catalogue | Ongoing |
| Alert flooding | Attacker buries a real alert under thousands of low-value ones | The scorecard tracks **precision**, not just volume — noise lowers the score | ✅ |
| Log-pipeline DoS | High-volume `eve.json` fills disk / overruns Loki | Loki retention + rate limits; alert on disk usage | Planned |
| Monitoring-plane exposure | Unauthenticated `0.0.0.0` binds on Prometheus/Grafana (F5) | Loopback binds + Grafana secret | **Open (M1)** |
| Privileged-container escape | cAdvisor `privileged` + host-root mount (F8) | Profile-gated, opt-in, read-only mounts, documented blast radius, never default | ✅ (accepted, isolated) |
| Supply-chain drift | Unpinned WireGuard image under `NET_ADMIN`+`SYS_MODULE` (F6); rolling ET Open | Digest pin (WG, open); ET Open content-pinned in `eval/ruleset.lock`; Trivy in CI | Partial |
| Secret leakage | Keys or `.env` committed | Narrowed `.gitignore`; gitleaks in CI **and** pre-commit; history verified clean | ✅ |
| **Measurement tampering** | Self-referential rules counted as real detection, inflating the score | Demo sids quarantined in `demo.rules`, excluded by the scorer, guarded in CI (`check-demo-rules.sh`) | ✅ |

The last row is specific to this project: the integrity of the *number* is itself an asset, and the closed-loop failure it guards against is the one the whole redesign exists to kill.

---

## Trust boundaries and invariants

```
   EXTERNAL_NET  ─┬─  WireGuard gateway (NET_ADMIN, SYS_MODULE)   ── highest privilege
                  │
   netguard-lab  ─┼─  monitored-app · traffic-gen · attack-sim    ── attacker-controlled data plane
                  │        │
                  │        └── Suricata (shared netns, NET_RAW)    ── observes the protected asset
                  │
   netguard-monitor ─┴─ Loki · Promtail · Prometheus · Grafana    ── control plane
```

Each invariant has a check that fails loudly if broken:

1. The attack-simulation container reaches only `netguard-lab`, never `netguard-monitor` — enforced by compose network attachment.
2. No image runs on a floating tag — Trivy + review (WireGuard pin still open, F6).
3. No secret is present in the tracked tree or git history — gitleaks (CI + pre-commit), `check-gitignore.sh`.
4. Every detection claim traces to a scored run at a named ruleset version — the scorecard stamps `ruleset.lock`; CI re-runs it.
5. No `demo.rules` signature is ever counted as detection — the scorer excludes those sids; `check-demo-rules.sh` asserts they stay isolated and in sync with the scorer's list.
6. (M1, open) No monitoring service is reachable from a non-loopback interface by default.

---

## Assumptions

- This is a local lab, not an internet-facing deployment. The first production-style deployment must close invariant 6 (loopback binds / authenticated ingress) and pin the WireGuard image.
- Operators run Docker with administrative privileges on a trusted workstation.
- Recall is measured against a fixed catalogue and is an upper bound on real-world recall, not an estimate of it (see the README's *Stated limitations*).

# NetGuard — 3-minute demo

A scripted walkthrough of the core story: **an attack launched and detected live, then measured.** Every command below is copy-pasteable; the expected output is the real output from a scored run. (A recorded screen capture belongs here too — this script is what it follows.)

> Prereqs: Docker Engine + Compose v2. From the repo root. Python optional (the scorer falls back to a container).

## 0 · Setup (once)

```sh
cp .env.example .env    # edit GRAFANA_ADMIN_PASSWORD
```

## 1 · Bring up the lab (~30–45 s) — the everyday state is benign

```sh
docker compose up -d --build suricata traffic-generator
docker compose ps
```

This fetches and **content-pins** ET Open (52k rules) into a volume, then starts Suricata in the monitored app's network namespace. The attack simulator is *not* started — `docker compose up` stays benign by design.

## 2 · Show the capture is alive (not detecting itself)

```sh
docker compose exec suricata sh -c \
  'grep -o "\"signature_id\":100000[1-4]" /var/log/suricata/eve.json | sort | uniq -c'
```

Expected — the four demo rules firing on the traffic generator:

```
     24 "signature_id":1000001
     12 "signature_id":1000002
     12 "signature_id":1000004
```

**Say:** these are the old self-referential rules. They prove the pipeline is alive — and they are *excluded* from the score. Detection has to come from somewhere the project doesn't control.

## 3 · Launch the attack catalogue and score it (~60–90 s)

```sh
SCENARIO=all ./scripts/run-catalogue.sh
```

This launches 10 attack techniques + 4 benign "negative controls" against the target, copies `eve.json` out of the volume, and scores it against the committed baseline. Expected tail:

```
recall 0.9  (9/10 attacks)   precision 1.0   FP 0   MTTD ~0.01s
baseline gate: PASS
```

Full table:

```
A01 SYN port scan            DETECTED    A06 Command injection   DETECTED
A02 Service/version scan     DETECTED    A07 Auth brute force    DETECTED
A03 Directory enumeration    DETECTED    A08 DNS tunneling       missed
A04 SQL injection            DETECTED    A09 C2 beaconing        DETECTED
A05 Reflected XSS            DETECTED    A10 Exfil over HTTP     DETECTED
N01–N04 negative controls    clean
```

**Say:** 9 of 10, precision 1.0, zero false positives. A08 is a *documented* miss — its DNS never traverses the monitored app's namespace, so the IDS can't see it. Reporting it as a miss instead of hiding it is the point.

## 4 · Prove a specific detection (optional close)

Show a real ET signature and an author rule firing on the attack source:

```sh
RUN=$(ls -dt runs/*/ | head -1)
grep '"src_ip":"10.10.0.40"' "${RUN}eve.json" \
  | grep -oE '"signature":"[^"]*"' | sort -u | head
```

Expected includes things like `ET WEB_SPECIFIC_APPS SQL Injection ...`, `ET SCAN Nmap ...`, and `NETGUARD LOCAL C2 beacon heuristic ...` (the author rule for A09).

## 5 · The honesty guarantee (optional)

Show that a dead capture can't fake a passing score:

```sh
python -m unittest tests.test_scorer -v   # 14 tests, incl. INVALID_RUN on dead capture
```

## Teardown

```sh
docker compose down          # keep data
docker compose down -v       # remove volumes (WireGuard, Loki, Prometheus, Grafana)
```

---

### The one-line version

> NetGuard launches a labeled catalogue of real attacks, scores what Suricata actually caught against a pinned ruleset, reports **9/10 at precision 1.0 with the one miss named**, and fails CI if that number ever regresses.

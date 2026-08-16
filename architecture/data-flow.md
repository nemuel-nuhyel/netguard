# NetGuard Data Flow

## Runtime traffic (data plane — `netguard-lab`)

1. The **traffic generator** sends benign HTTP/DNS/TCP probes to `monitored-app`, producing the demo-sid alerts that prove the pipeline is alive.
2. When invoked (`profile: attack`), the **attack simulator** launches the labeled catalogue against `monitored-app` — scans, web attacks, a beacon, an exfil POST — from `10.10.0.40`.
3. **Suricata** runs inside `monitored-app`'s network namespace (`network_mode: service:monitored-app`) and inspects its `eth0`, so it sees exactly the traffic reaching the protected asset. `HOME_NET` is the monitored app, so both generators are `EXTERNAL_NET`.
4. Suricata writes structured events to `/var/log/suricata/eve.json` in the shared `suricata-logs` volume.

## Detection measurement

1. The attack simulator writes a self-describing `manifest.json` (each technique's window, ATT&CK id, expected signature class) into `runs/<ts>/`.
2. `scripts/run-catalogue.sh` copies `eve.json` out of the volume into the same run directory.
3. `netguard/scorer.py` joins the manifest against `eve.json` on time window **and** source IP, excludes demo sids, and writes `scorecard.json` — recall, precision, FP, MTTD — gated against `eval/baseline.json`.

## Log flow (control plane — `netguard-monitor`)

1. **Promtail** tails `eve.json` from the read-only Suricata log volume and parses `event_type`, `src_ip`, `dest_ip`, `dest_port`, `proto`, and alert severity.
2. Promtail pushes events to **Loki**.
3. **Grafana** queries Loki for alert / DNS / HTTP / flow panels.

## Metrics flow

1. **cAdvisor** (opt-in, `profile: cadvisor`) reads Docker/host cgroup data.
2. **Prometheus** scrapes cAdvisor, Loki, Promtail, Grafana, and itself.
3. **Grafana** queries Prometheus for container CPU/memory and scrape-health panels.

## Trust boundaries

- `netguard-lab` — attacker-controlled data plane (app, generators, attack-sim, Suricata's shared netns).
- `netguard-monitor` — observability plane (Loki, Promtail, Prometheus, cAdvisor, Grafana).
- `netguard-mgmt` — operator-facing services (Grafana, WireGuard gateway).

The attack simulator is attached only to `netguard-lab` and cannot reach `netguard-monitor` (threat-model invariant 1).

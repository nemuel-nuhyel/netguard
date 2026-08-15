# NetGuard Data Flow

## Runtime Traffic

1. The safe traffic generator sends HTTP requests to `monitored-app`, performs a DNS lookup, and attempts a TCP connection to expected and unexpected ports.
2. The WireGuard gateway provides the VPN entry point for future remote lab clients.
3. Suricata runs in host network mode and captures packets from the host interfaces, including Docker bridge traffic on Linux hosts.
4. Suricata writes structured events to `/var/log/suricata/eve.json` in the shared `suricata-logs` Docker volume.

## Log Flow

1. Promtail tails `eve.json` from the shared read-only Suricata log volume.
2. Promtail parses core JSON fields such as `event_type`, `src_ip`, `dest_ip`, `dest_port`, `proto`, and alert severity.
3. Promtail pushes events to Loki.
4. Grafana queries Loki for Suricata alert, DNS, HTTP, and flow panels.

## Metrics Flow

1. cAdvisor reads Docker and host cgroup data.
2. Prometheus scrapes cAdvisor, Loki, Promtail, Grafana, and itself.
3. Grafana queries Prometheus for container CPU, memory, and scrape health panels.

## Trust Boundaries

- `netguard-lab` carries demo application and VPN-facing lab traffic.
- `netguard-monitor` carries observability traffic between Prometheus, Loki, Promtail, cAdvisor, and Grafana.
- `netguard-mgmt` carries operator-facing services such as Grafana and the WireGuard gateway.

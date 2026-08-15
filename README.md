# NetGuard 2.0

NetGuard is a containerized security monitoring lab built around WireGuard, Suricata, Loki, Prometheus, cAdvisor, and Grafana. Sprint 1 focuses on observability: collect network security events, collect container metrics, and expose both through provisioned Grafana dashboards.

## What Sprint 1 Includes

- Segmented Docker networks for management, lab traffic, and monitoring traffic.
- WireGuard gateway container with generated runtime configuration stored in a Docker volume.
- Suricata IDS configured for structured `eve.json` output and local lab rules.
- Promtail shipping Suricata `eve.json` events to Loki.
- Prometheus scraping container metrics from cAdvisor and service health endpoints.
- Grafana provisioned with Loki and Prometheus datasources plus a security overview dashboard.
- Safe traffic generator that creates repeatable HTTP, DNS, and TCP probe activity for dashboards.
- Health checks on every service.

## Requirements

- Docker Engine with Compose v2.
- Linux or WSL2-backed Docker is recommended for Suricata host packet capture and cAdvisor host mounts.
- UDP `51820` available on the host for WireGuard.

This repository does not commit VPN private keys, Grafana runtime data, Loki data, or generated logs.

## Quick Start

1. Create a local environment file:

   ```sh
   cp .env.example .env
   ```

2. Change `GRAFANA_ADMIN_PASSWORD` in `.env`.

3. Start the lab:

   ```sh
   docker compose up -d --build
   ```

   cAdvisor is optional and is disabled by default because Docker Desktop on
   Windows can fail while inspecting or pulling the cAdvisor image. To include
   container metrics after Docker image pulls are working, start with:

   ```sh
   docker compose --profile cadvisor up -d --build
   ```

4. Check service health:

   ```sh
   docker compose ps
   ```

5. Open Grafana:

   - URL: `http://localhost:3000`
   - User: value of `GRAFANA_ADMIN_USER`
   - Password: value of `GRAFANA_ADMIN_PASSWORD`

6. Open the `NetGuard Security Overview` dashboard. Within 30 seconds, the safe traffic generator should create events visible in Loki-backed panels and container metrics should appear from Prometheus.

## Useful Commands

```sh
docker compose logs -f suricata
docker compose logs -f promtail
docker compose logs -f traffic-generator
docker compose exec prometheus wget -qO- http://localhost:9090/-/healthy
docker compose down
docker compose down -v
```

Use `docker compose down -v` only when you want to remove generated WireGuard, Loki, Prometheus, and Grafana data.

## Service Map

| Service | Purpose | Default URL / Port |
| --- | --- | --- |
| `wireguard` | VPN gateway into the lab network | UDP `51820` |
| `suricata` | IDS packet capture and `eve.json` producer | host network capture |
| `monitored-app` | Nginx target for safe lab traffic | internal only |
| `traffic-generator` | Repeatable benign HTTP, DNS, and TCP activity | internal only |
| `promtail` | Ships Suricata logs to Loki | `9080` internal |
| `loki` | Central log store | `3100` internal |
| `prometheus` | Metrics store | `http://localhost:9090` |
| `cadvisor` | Optional Docker/container metrics exporter | `8080` internal |
| `grafana` | Dashboards for logs and metrics | `http://localhost:3000` |

## Validation

Validate Compose syntax:

```sh
docker compose config
```

Validate Suricata config and local rules:

```sh
./scripts/validate-rules.sh
```

Generate traffic manually:

```sh
docker compose logs -f traffic-generator
```

Expected Suricata alerts come from `services/suricata/rules/local.rules`, especially the traffic-generator user agent and `/admin` probe rule.

## Architecture Docs

- `architecture/architecture-diagram.mmd`
- `architecture/data-flow.md`
- `architecture/threat-model.md`

## Notes

Suricata is configured with `network_mode: host` so it can observe Docker bridge traffic on Linux hosts. Docker Desktop behavior differs by platform; if packet capture is unavailable on your host, Suricata can still validate rules and the rest of the monitoring stack can run, but live network detections may be limited.

The response engine, GitLab CI/CD pipeline, and AI incident analyst are intentionally not included in Sprint 1. They build on this observability foundation in later phases.

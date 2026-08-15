# NetGuard Sprint 1 Threat Model

## Assets

- WireGuard private keys and generated peer configuration.
- Suricata `eve.json` security events.
- Grafana dashboards and admin credentials.
- Loki and Prometheus runtime data.
- Host Docker socket, cgroups, and container metadata exposed to cAdvisor.

## Main Risks

| Risk | Control |
| --- | --- |
| VPN keys committed to Git | Generated configs live in Docker volumes; `.gitignore` excludes `*.key`, `*.conf`, `.env`, and config contents. |
| Grafana default password reused | `.env.example` uses a placeholder and README requires changing it before startup. |
| Monitoring ports exposed unnecessarily | Only Grafana, Prometheus, and WireGuard are published by default; Loki, Promtail, and cAdvisor stay internal. |
| Suricata cannot see lab traffic on non-Linux hosts | README documents host packet capture expectations and platform limitations. |
| Unsafe demo traffic | Traffic generator uses benign HTTP, DNS, and TCP probes with a configurable low request interval. |
| Excessive automated response | No blocking or firewall automation exists in Sprint 1; response automation is deferred until observability is proven. |

## Assumptions

- This is a local lab, not an internet-facing production deployment.
- Operators run Docker with administrative privileges on a trusted workstation.
- The first production-style deployment will add authenticated ingress and stricter host firewall rules.

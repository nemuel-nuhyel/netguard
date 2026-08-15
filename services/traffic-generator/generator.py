import os
import socket
import time
import urllib.error
import urllib.request


APP_URL = os.getenv("APP_URL", "http://monitored-app/").rstrip("/") + "/"
INTERVAL_SECONDS = int(os.getenv("INTERVAL_SECONDS", "10"))
DNS_PROBE_HOST = os.getenv("DNS_PROBE_HOST", "example.com")
PORT_PROBE_HOST = os.getenv("PORT_PROBE_HOST", "monitored-app")
PORT_PROBE_PORTS = [
    int(port.strip())
    for port in os.getenv("PORT_PROBE_PORTS", "80,8080").split(",")
    if port.strip()
]
HEALTH_FILE = "/tmp/traffic-generator.health"


def touch_health() -> None:
    with open(HEALTH_FILE, "w", encoding="utf-8") as health_file:
        health_file.write(str(int(time.time())))


def fetch(path: str) -> None:
    request = urllib.request.Request(
        APP_URL + path.lstrip("/"),
        headers={
            "User-Agent": "NetGuardTrafficGenerator/1.0",
            "X-NetGuard-Lab": "safe-demo",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            print(f"http {path} -> {response.status}", flush=True)
    except urllib.error.HTTPError as exc:
        print(f"http {path} -> {exc.code}", flush=True)
    except OSError as exc:
        print(f"http {path} failed: {exc}", flush=True)


def dns_probe() -> None:
    try:
        addresses = socket.getaddrinfo(DNS_PROBE_HOST, 80)
        print(f"dns {DNS_PROBE_HOST} -> {len(addresses)} answers", flush=True)
    except OSError as exc:
        print(f"dns {DNS_PROBE_HOST} failed: {exc}", flush=True)


def port_probe(port: int) -> None:
    try:
        with socket.create_connection((PORT_PROBE_HOST, port), timeout=2):
            print(f"tcp {PORT_PROBE_HOST}:{port} -> open", flush=True)
    except OSError as exc:
        print(f"tcp {PORT_PROBE_HOST}:{port} -> closed/refused ({exc})", flush=True)


def main() -> None:
    print("starting NetGuard safe traffic generator", flush=True)

    while True:
        touch_health()
        fetch("/")
        fetch("/admin/netguard-lab")
        dns_probe()
        for port in PORT_PROBE_PORTS:
            port_probe(port)
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()

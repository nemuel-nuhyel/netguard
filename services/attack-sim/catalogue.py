"""The NetGuard attack catalogue — this table *is* the test spec (plan §4.2).

Each entry pairs a technique with its ATT&CK mapping, the tool that produces it,
and the signature class that a competent ruleset is *expected* to fire. The
attack-sim driver runs these against the monitored app and stamps the real
start/end timestamps into a manifest; the scorer joins that manifest against
Suricata's eve.json to compute recall, precision and false positives.

`expected` is the detection matcher the scorer uses. An alert counts as a hit
for an entry when its `signature` contains any `any_sig_substr` (case-insensitive)
OR its `category` (the Suricata classtype description) contains any
`any_classtype`. The four self-referential demo rules (sids 1000001–1000004) are
NEVER counted as detection (ADR-003) — they only prove the pipeline is alive.

`kind`:
  "attack"   → a hit is a true positive; contributes to recall.
  "negative" → a hit is a FALSE positive; benign traffic that must NOT alert.
"""

# The self-referential Sprint-1 rules. Alerts from these sids validate that the
# capture+detection pipeline is alive, but are excluded from real detection.
DEMO_SIDS = [1000001, 1000002, 1000003, 1000004]

CATALOGUE = [
    # ── Attacks (A01–A10) ────────────────────────────────────────────────
    {
        "id": "A01",
        "name": "SYN port scan",
        "attack_id": "T1046",
        "tool": "nmap -sS",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["scan", "nmap", "port scan", "portscan"],
            "any_classtype": ["attempted-recon", "network-scan", "detection of a"],
        },
    },
    {
        "id": "A02",
        "name": "Service/version scan",
        "attack_id": "T1046",
        "tool": "nmap -sV",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["scan", "nmap", "version"],
            "any_classtype": ["attempted-recon", "network-scan"],
        },
    },
    {
        "id": "A03",
        "name": "Directory enumeration",
        "attack_id": "T1083",
        "tool": "python dir-enum driver",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["web_server", "dir", "enumeration", "nikto", "gobuster", "crawler"],
            "any_classtype": ["web-application-attack", "attempted-recon"],
        },
    },
    {
        "id": "A04",
        "name": "SQL injection",
        "attack_id": "T1190",
        "tool": "python sqli driver",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["sql injection", "sqli", "web_specific_apps", "union select"],
            "any_classtype": ["web-application-attack"],
        },
    },
    {
        "id": "A05",
        "name": "Reflected XSS",
        "attack_id": "T1059",
        "tool": "python xss driver",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["xss", "cross site scripting", "web_server"],
            "any_classtype": ["web-application-attack"],
        },
    },
    {
        "id": "A06",
        "name": "Command injection attempt",
        "attack_id": "T1190",
        "tool": "python cmdi driver",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["command injection", "cmd injection", "web_specific", "/bin/sh", "shell"],
            "any_classtype": ["web-application-attack"],
        },
    },
    {
        "id": "A07",
        "name": "HTTP auth brute force",
        "attack_id": "T1110",
        "tool": "python brute driver",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["brute", "brute force", "login", "auth"],
            "any_classtype": ["attempted-user", "attempted-recon"],
        },
    },
    {
        "id": "A08",
        "name": "DNS tunneling",
        "attack_id": "T1071.004",
        "tool": "python dns-tunnel sim",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["dns", "tunnel", "query length", "exfil"],
            "any_classtype": ["bad-unknown", "policy-violation"],
        },
    },
    {
        "id": "A09",
        "name": "C2 beaconing (periodic)",
        "attack_id": "T1071",
        "tool": "python beacon sim",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["malware", "beacon", "c2", "checkin", "trojan"],
            "any_classtype": ["trojan-activity", "command-and-control"],
        },
    },
    {
        "id": "A10",
        "name": "Suspicious outbound volume",
        "attack_id": "T1048",
        "tool": "python bulk-transfer sim",
        "kind": "attack",
        "expected": {
            "any_sig_substr": ["exfil", "exfiltration", "large", "data transfer"],
            "any_classtype": ["policy-violation", "bad-unknown"],
        },
    },
    # ── Negative controls (N01–N04): benign, must NOT alert as attack ─────
    {
        "id": "N01",
        "name": "Legitimate admin login",
        "attack_id": "-",
        "tool": "python driver",
        "kind": "negative",
        "expected": {
            "any_sig_substr": ["brute", "brute force"],
            "any_classtype": ["attempted-user"],
        },
    },
    {
        "id": "N02",
        "name": "Large legitimate download",
        "attack_id": "-",
        "tool": "python driver",
        "kind": "negative",
        "expected": {
            "any_sig_substr": ["exfil", "exfiltration", "large"],
            "any_classtype": ["policy-violation"],
        },
    },
    {
        "id": "N03",
        "name": "Rapid but normal API polling",
        "attack_id": "-",
        "tool": "python driver",
        "kind": "negative",
        "expected": {
            "any_sig_substr": ["scan", "portscan", "port scan"],
            "any_classtype": ["network-scan", "attempted-recon"],
        },
    },
    {
        "id": "N04",
        "name": "DNS lookups for many distinct real hosts",
        "attack_id": "-",
        "tool": "python driver",
        "kind": "negative",
        "expected": {
            "any_sig_substr": ["tunnel", "dns", "query length"],
            "any_classtype": ["bad-unknown"],
        },
    },
]

# Convenience groupings the driver understands as SCENARIO values.
ATTACK_IDS = [e["id"] for e in CATALOGUE if e["kind"] == "attack"]
NEGATIVE_IDS = [e["id"] for e in CATALOGUE if e["kind"] == "negative"]
BY_ID = {e["id"]: e for e in CATALOGUE}


def select(scenario: str):
    """Resolve a SCENARIO string to an ordered list of catalogue entries."""
    scenario = (scenario or "all").strip().lower()
    if scenario in ("all", ""):
        ids = [e["id"] for e in CATALOGUE]
    elif scenario in ("attacks", "attack"):
        ids = ATTACK_IDS
    elif scenario in ("negatives", "negative", "controls"):
        ids = NEGATIVE_IDS
    else:
        ids = [tok.strip().upper() for tok in scenario.split(",") if tok.strip()]
    return [BY_ID[i] for i in ids if i in BY_ID]

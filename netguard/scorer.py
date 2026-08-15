"""Detection scorer — the denominator the Sprint-1 lab never had (plan §4.3, §5).

Joins an attack-sim manifest (labeled technique windows) against Suricata's
eve.json and reports, at a named ruleset version:

    recall     = attack techniques detected / attack techniques launched
    precision  = true-positive alerts / (true positives + false positives)
    fp_count   = alerts fired inside negative-control windows
    MTTD       = median seconds from technique start to its first alert

Two guards keep the number honest:

  * The four self-referential demo rules (sids 1000001–1000004) are NEVER
    counted as detection (ADR-003). Counting them is the closed loop that made
    Sprint 1's claim hollow.

  * If Suricata captured nothing, the scorer refuses to emit a score. It marks
    the run INVALID rather than reporting a misleading 0/10 — a dead capture and
    a ruleset that misses everything must not look identical (F4). Liveness is
    proven by demo-sid alerts (the generator triggers them every ~10s) or any
    non-stats eve event inside the run window.

Pure functions (`parse_eve_timestamp`, `load_events`, `score`) carry the logic
so it is unit-testable without a live stack — see tests/test_scorer.py.

Usage (see also scripts/run-catalogue.sh, which copies eve.json out of the
suricata-logs volume first):

    python -m netguard.scorer \
        --manifest runs/<ts>/manifest.json \
        --eve      runs/<ts>/eve.json \
        --baseline eval/baseline.json \
        --out      runs/<ts>/scorecard.json
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import time

SCHEMA = "netguard-scorecard/1"

# Windows are padded so a technique's alert, which lands a beat after the
# payload, still falls inside the join window.
DEFAULT_PRE = 2.0
DEFAULT_POST = 10.0

# eve stats events fire on a timer even with zero traffic, so they are not proof
# that anything was captured. Everything else counts toward liveness.
_LIVENESS_EVENT_TYPES = {"alert", "http", "dns", "tls", "flow", "fileinfo", "anomaly"}

_TS_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<frac>\.\d+)?\s*(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)


def parse_eve_timestamp(value: str) -> float:
    """Parse a Suricata eve timestamp to epoch seconds (UTC).

    Suricata writes e.g. ``2026-08-15T20:39:00.123456+0000`` — an offset with no
    colon, which ``datetime.fromisoformat`` rejects before Python 3.11. We parse
    it explicitly so the result is correct on any interpreter and independent of
    the host timezone. A missing offset is treated as UTC.
    """
    m = _TS_RE.match(value.strip())
    if not m:
        raise ValueError(f"unrecognized eve timestamp: {value!r}")

    y, mo, d = (int(x) for x in m.group("date").split("-"))
    hh, mm, ss = (int(x) for x in m.group("time").split(":"))
    frac = float(m.group("frac")) if m.group("frac") else 0.0

    tz = m.group("tz")
    offset = 0
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)

    # timegm treats the tuple as UTC; subtract the offset to get true UTC epoch.
    import calendar

    wall = calendar.timegm((y, mo, d, hh, mm, ss, 0, 0, 0))
    return wall - offset + frac


def load_events(path: str) -> list[dict]:
    """Read eve.json (one JSON object per line) into normalized event dicts.

    Malformed lines are skipped rather than aborting a whole run. Only fields the
    scorer needs are kept.
    """
    events: list[dict] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = raw.get("timestamp")
            try:
                epoch = parse_eve_timestamp(ts) if ts else None
            except ValueError:
                epoch = None
            evt = {
                "event_type": raw.get("event_type", ""),
                "epoch": epoch,
                "src_ip": raw.get("src_ip"),
                "dest_ip": raw.get("dest_ip"),
            }
            if raw.get("event_type") == "alert":
                alert = raw.get("alert") or {}
                evt["signature"] = str(alert.get("signature", ""))
                evt["category"] = str(alert.get("category", ""))
                try:
                    evt["sid"] = int(alert.get("signature_id"))
                except (TypeError, ValueError):
                    evt["sid"] = None
            events.append(evt)
    return events


def _matches(evt: dict, expected: dict) -> bool:
    """True if an alert's signature or category satisfies an entry's matcher."""
    sig = evt.get("signature", "").lower()
    cat = evt.get("category", "").lower()
    for sub in expected.get("any_sig_substr", []):
        if sub.lower() in sig:
            return True
    for sub in expected.get("any_classtype", []):
        if sub.lower() in cat:
            return True
    return False


def _run_window(entries: list[dict], pre: float, post: float):
    starts = [e["start_epoch"] for e in entries if "start_epoch" in e]
    ends = [e["end_epoch"] for e in entries if "end_epoch" in e]
    if not starts or not ends:
        return None, None
    return min(starts) - pre, max(ends) + post


def score(
    manifest: dict,
    events: list[dict],
    *,
    pre: float = DEFAULT_PRE,
    post: float = DEFAULT_POST,
) -> dict:
    """Compute the scorecard. Pure over parsed inputs — unit-testable."""
    meta = manifest.get("meta", {})
    demo_sids = set(meta.get("demo_sids", []))
    sim_ip = meta.get("sim_ip") or None
    entries = manifest.get("entries", [])

    alerts = [e for e in events if e["event_type"] == "alert" and e["epoch"] is not None]
    run_start, run_end = _run_window(entries, pre, post)

    # ── Capture liveness ──────────────────────────────────────────────────
    in_run = lambda ep: run_start is not None and run_start <= ep <= run_end  # noqa: E731
    demo_alerts = [a for a in alerts if a.get("sid") in demo_sids and in_run(a["epoch"])]
    live_events = [
        e for e in events
        if e["event_type"] in _LIVENESS_EVENT_TYPES and e["epoch"] is not None and in_run(e["epoch"])
    ]
    capture_live = bool(demo_alerts) or bool(live_events)

    capture = {
        "live": capture_live,
        "demo_alerts": len(demo_alerts),
        "events_in_window": len(live_events),
    }

    notes: list[str] = []
    if sim_ip is None:
        notes.append(
            "manifest has no sim_ip; alerts are attributed by time window only, "
            "which may credit the traffic-generator's alerts to techniques."
        )

    if not capture_live:
        capture["reason"] = (
            "no demo-sid alerts and no non-stats eve events inside the run window "
            "— Suricata captured nothing (see F4: host-mode capture is dead on "
            "Windows/macOS until M1's namespace-sharing fix)."
        )
        return {
            "schema": SCHEMA,
            "result": "INVALID_RUN",
            "valid": False,
            "run_id": meta.get("run_id"),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ruleset_version": meta.get("ruleset_version"),
            "suricata_version": meta.get("suricata_version"),
            "capture": capture,
            "aggregate": None,
            "per_technique": [],
            "notes": notes + [capture["reason"]],
        }

    # Only alerts attributable to the simulator count. This excludes the
    # continuously-running traffic-generator (10.10.0.30), whose windows would
    # otherwise smear into every technique.
    def attributable(a: dict) -> bool:
        if a.get("sid") in demo_sids:
            return False
        if sim_ip is not None and a.get("src_ip") != sim_ip:
            return False
        return True

    sim_alerts = [a for a in alerts if attributable(a)]

    def in_entry_window(a: dict, entry: dict) -> bool:
        if not (entry["start_epoch"] - pre <= a["epoch"] <= entry["end_epoch"] + post):
            return False
        dest = entry.get("dest_ip")
        if dest and a.get("dest_ip") and a["dest_ip"] != dest:
            return False
        return True

    per_technique = []
    detected_delays: list[float] = []
    tp_alerts = 0
    fp_alerts = 0
    attacks_total = 0
    attacks_detected = 0

    for entry in entries:
        if "start_epoch" not in entry:
            continue
        hits = [a for a in sim_alerts if in_entry_window(a, entry) and _matches(a, entry["expected"])]
        row = {
            "id": entry["id"],
            "name": entry.get("name"),
            "attack_id": entry.get("attack_id"),
            "kind": entry["kind"],
            "alert_count": len(hits),
            "matched_signatures": sorted({h["signature"] for h in hits})[:5],
        }
        if entry["kind"] == "attack":
            attacks_total += 1
            detected = len(hits) > 0
            row["detected"] = detected
            if detected:
                attacks_detected += 1
                first = min(h["epoch"] for h in hits)
                delay = round(first - entry["start_epoch"], 3)
                row["first_alert_delay_s"] = delay
                detected_delays.append(delay)
                tp_alerts += len(hits)
            else:
                row["first_alert_delay_s"] = None
        else:  # negative control: any hit is a false positive
            fp = len(hits) > 0
            row["false_positive"] = fp
            fp_alerts += len(hits)
        per_technique.append(row)

    recall = round(attacks_detected / attacks_total, 4) if attacks_total else None
    denom = tp_alerts + fp_alerts
    precision = round(tp_alerts / denom, 4) if denom else None
    mttd = round(statistics.median(detected_delays), 3) if detected_delays else None

    aggregate = {
        "recall": recall,
        "attacks_total": attacks_total,
        "attacks_detected": attacks_detected,
        "precision": precision,
        "tp_alerts": tp_alerts,
        "fp_alerts": fp_alerts,
        "fp_count": fp_alerts,
        "mttd_seconds": mttd,
    }

    return {
        "schema": SCHEMA,
        "result": "SCORED",
        "valid": True,
        "run_id": meta.get("run_id"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ruleset_version": meta.get("ruleset_version"),
        "suricata_version": meta.get("suricata_version"),
        "capture": capture,
        "aggregate": aggregate,
        "per_technique": per_technique,
        "notes": notes,
    }


def compare_baseline(card: dict, baseline: dict) -> dict:
    """Compare a scored card against a committed baseline; produce a CI gate."""
    if baseline.get("status") == "not_yet_run" or not baseline.get("metrics"):
        return {
            "status": "no_baseline",
            "gate": "skipped",
            "message": "baseline not yet established; run the catalogue to seed eval/baseline.json",
        }
    agg = card.get("aggregate") or {}
    base = baseline["metrics"]
    recall_now, recall_base = agg.get("recall"), base.get("recall")
    fp_now, fp_base = agg.get("fp_count"), base.get("fp_count")

    reasons = []
    if recall_base is not None and recall_now is not None and recall_now < recall_base:
        reasons.append(f"recall regressed: {recall_now} < baseline {recall_base}")
    if fp_base is not None and fp_now is not None and fp_now > fp_base:
        reasons.append(f"false positives rose: {fp_now} > baseline {fp_base}")

    return {
        "status": "compared",
        "gate": "fail" if reasons else "pass",
        "reasons": reasons,
        "recall": {"now": recall_now, "baseline": recall_base},
        "fp_count": {"now": fp_now, "baseline": fp_base},
    }


def render_table(card: dict, baseline_cmp: dict | None = None) -> str:
    lines = []
    lines.append("=" * 68)
    lines.append(f"NetGuard detection scorecard — run {card.get('run_id')}")
    lines.append(
        f"ruleset: {card.get('ruleset_version') or 'unset'}   "
        f"suricata: {card.get('suricata_version') or 'unset'}"
    )
    lines.append("=" * 68)

    if not card.get("valid"):
        cap = card.get("capture", {})
        lines.append(f"RESULT: {card.get('result')}  (no score emitted)")
        lines.append(f"  capture live: {cap.get('live')}   demo alerts: {cap.get('demo_alerts')}   "
                     f"events in window: {cap.get('events_in_window')}")
        for n in card.get("notes", []):
            lines.append(f"  ! {n}")
        lines.append("=" * 68)
        return "\n".join(lines)

    agg = card["aggregate"]
    lines.append(f"{'ID':<5}{'KIND':<10}{'TECHNIQUE':<30}{'RESULT':<12}{'ALERTS':>7}")
    lines.append("-" * 68)
    for r in card["per_technique"]:
        if r["kind"] == "attack":
            res = "DETECTED" if r.get("detected") else "missed"
        else:
            res = "FALSE POS" if r.get("false_positive") else "clean"
        lines.append(
            f"{r['id']:<5}{r['kind']:<10}{(r.get('name') or '')[:29]:<30}{res:<12}{r['alert_count']:>7}"
        )
    lines.append("-" * 68)
    lines.append(
        f"recall {agg['recall']}  "
        f"({agg['attacks_detected']}/{agg['attacks_total']} attacks)   "
        f"precision {agg['precision']}   "
        f"FP {agg['fp_count']}   "
        f"MTTD {agg['mttd_seconds']}s"
    )
    lines.append(
        f"capture live: {card['capture']['live']}  "
        f"(demo alerts {card['capture']['demo_alerts']}, "
        f"events {card['capture']['events_in_window']})"
    )
    for n in card.get("notes", []):
        lines.append(f"  ! {n}")
    if baseline_cmp:
        if baseline_cmp["status"] == "compared":
            lines.append(f"baseline gate: {baseline_cmp['gate'].upper()}")
            for reason in baseline_cmp.get("reasons", []):
                lines.append(f"    - {reason}")
        else:
            lines.append(f"baseline gate: {baseline_cmp['gate']} — {baseline_cmp['message']}")
    lines.append("=" * 68)
    return "\n".join(lines)


def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m netguard.scorer",
        description="Score Suricata detection against a labeled attack-sim manifest.",
    )
    ap.add_argument("--manifest", required=True, help="attack-sim manifest.json")
    ap.add_argument("--eve", required=True, help="Suricata eve.json (copied out of the volume)")
    ap.add_argument("--baseline", help="eval/baseline.json to gate against")
    ap.add_argument("--out", help="write scorecard.json here")
    ap.add_argument("--ruleset-version", help="override/stamp the ruleset version")
    ap.add_argument("--suricata-version", help="override/stamp the Suricata version")
    ap.add_argument("--pre", type=float, default=DEFAULT_PRE, help="seconds of pre-window padding")
    ap.add_argument("--post", type=float, default=DEFAULT_POST, help="seconds of post-window padding")
    ap.add_argument("--json", action="store_true", help="print scorecard JSON instead of the table")
    args = ap.parse_args(argv)

    manifest = _read_json(args.manifest)
    if args.ruleset_version:
        manifest.setdefault("meta", {})["ruleset_version"] = args.ruleset_version
    if args.suricata_version:
        manifest.setdefault("meta", {})["suricata_version"] = args.suricata_version

    events = load_events(args.eve)
    card = score(manifest, events, pre=args.pre, post=args.post)

    baseline_cmp = None
    if args.baseline:
        try:
            baseline = _read_json(args.baseline)
            baseline_cmp = compare_baseline(card, baseline)
            card["baseline"] = baseline_cmp
        except FileNotFoundError:
            card["baseline"] = {"status": "missing", "gate": "skipped"}

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(card, fh, indent=2)

    if args.json:
        print(json.dumps(card, indent=2))
    else:
        print(render_table(card, baseline_cmp))

    # Exit non-zero on an invalid run or a failed baseline gate, so CI catches it.
    if not card.get("valid"):
        return 3
    if baseline_cmp and baseline_cmp.get("gate") == "fail":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

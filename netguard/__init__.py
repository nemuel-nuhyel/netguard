"""NetGuard detection-measurement toolkit.

`netguard.scorer` joins an attack-sim manifest against Suricata's eve.json and
computes recall, precision, false-positive count and MTTD — turning the
detection claim into a measured number (plan §4–§5).
"""

__all__ = ["scorer"]

"""
Simple rule-based detection engine for AEGIS AI.

This is a rule-based prototype, NOT a trained AI model.
Detection logic is kept in this file so an ML model can be added later.
"""

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Thresholds per source IP inside a sliding time window
THRESHOLDS = {
    "port_scan": {"distinct_ports": 8, "min_records": 5},
    "ddos": {"total_bytes": 100000},
    "brute_force": {"attempts": 6, "dst_ports": (21, 22, 23, 25, 3389)},
    "suspicious": {"total_packets": 20000, "avg_packet": 60},
}


def detect(record, history):
    """
    Evaluate a single traffic record against the rules.

    record: dict with keys timestamp, src_ip, dst_ip, protocol,
            src_port, dst_port, packet_size
    history: list of previously stored traffic rows (dicts) sharing the
            same src_ip, used for volume/scan/ brute-force analysis.

    Returns dict: {detection, severity, reason}
    """
    same_ip = [h for h in history if h["src_ip"] == record["src_ip"]]
    now = record["timestamp"]

    # Rule: DDoS — extremely high traffic volume from one source
    window = [r for r in same_ip if r["timestamp"] >= now[:13]]  # same hour bucket
    total_bytes = sum(r["packet_size"] or 0 for r in window)
    if total_bytes >= THRESHOLDS["ddos"]["total_bytes"]:
        return {
            "detection": "DDoS",
            "severity": "CRITICAL",
            "reason": f"High traffic volume: {total_bytes} bytes in the same time window",
        }

    # Rule: Port scan — connections to many distinct destination ports
    distinct_ports = {r["dst_port"] for r in same_ip if r["dst_port"]}
    if len(same_ip) >= THRESHOLDS["port_scan"]["min_records"] and len(distinct_ports) >= THRESHOLDS["port_scan"]["distinct_ports"]:
        return {
            "detection": "PORT SCAN",
            "severity": "HIGH",
            "reason": f"{len(same_ip)} connection attempts to {len(distinct_ports)} distinct ports",
        }

    # Rule: Brute force — repeated login attempts to auth-related ports
    auth_ports = THRESHOLDS["brute_force"]["dst_ports"]
    auth_attempts = [r for r in same_ip if r["dst_port"] in auth_ports]
    if len(auth_attempts) >= THRESHOLDS["brute_force"]["attempts"]:
        return {
            "detection": "BRUTE FORCE",
            "severity": "HIGH",
            "reason": f"{len(auth_attempts)} repeated login attempts to port(s) {sorted(auth_ports)}",
        }

    # Rule: Suspicious — unusual traffic patterns (large packets on odd ports)
    odd_ports = {r["dst_port"] for r in same_ip if r["dst_port"] and r["dst_port"] < 1024}
    if record["packet_size"] and record["packet_size"] >= THRESHOLDS["suspicious"]["avg_packet"] * 40 and len(odd_ports) >= 3:
        return {
            "detection": "SUSPICIOUS",
            "severity": "MEDIUM",
            "reason": "Unusual traffic pattern: large payloads across multiple low ports",
        }

    return {"detection": "BENIGN", "severity": "LOW", "reason": "Normal traffic pattern"}


def worst_severity(results):
    """Return the highest severity among a list of detection results."""
    best = "LOW"
    for r in results:
        if SEVERITY_ORDER.get(r["severity"], 0) > SEVERITY_ORDER.get(best, 0):
            best = r["severity"]
    return best

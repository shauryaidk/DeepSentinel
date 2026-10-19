import ipaddress
from collections import defaultdict
from functools import lru_cache

from .c2_beacon import detect_beacon
from .network_scanner import detect_scans


def run_temporal_graph_engine(packet_batch: list[dict]) -> dict:
    """
    Main evaluation pipeline.
    Expected packet schema:
    [
      {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 443, "timestamp": 1720000001.2},
      ...
    ]
    """
    if not packet_batch:
        return {"status": "ok", "alerts": []}

    alerts = []

    scan_alerts = detect_scans(packet_batch)
    alerts.extend(scan_alerts)

    # v3: a beacon is periodic traffic from one internal host to ONE destination.
    # v2 pooled all of a host's traffic, so bursty browsing and DDoS bots
    # (external sources) were flagged as beacons.
    pair_ts = defaultdict(list)
    for p in packet_batch:
        if _is_internal(p["src_ip"]):
            pair_ts[(p["src_ip"], p["dst_ip"])].append(p["timestamp"])

    beaconing = {}
    for (src_ip, dst_ip), ts_list in pair_ts.items():
        beacon_result = detect_beacon(ts_list)
        if beacon_result["alert"] and beacon_result["confidence"] > beaconing.get(src_ip, {}).get("confidence", -1):
            beaconing[src_ip] = {"src_ip": src_ip, "target_ip": dst_ip, **beacon_result}
    alerts.extend(beaconing.values())

    return {
        "status": "threat_detected" if alerts else "clean",
        "alert_count": len(alerts),
        "alerts": alerts,
    }


@lru_cache(maxsize=65536)
def _is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

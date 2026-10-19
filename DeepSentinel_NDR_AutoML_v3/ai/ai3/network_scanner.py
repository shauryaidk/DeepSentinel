from collections import defaultdict
import numpy as np


def detect_scans(
    records: list[dict],
    horizontal_threshold: int = 15,
    vertical_threshold: int = 10,
    min_scan_rate_pps: float = 2.0,
    window_s: float | None = 60.0,
) -> list[dict]:
    """
    Builds dynamic bipartite graphs (Src -> Dst, Src -> Port) to catch reconnaissance.
    records expected format: [{'src_ip': str, 'dst_ip': str, 'dst_port': int, 'timestamp': float}, ...]

    v3: only the last `window_s` seconds of the batch are used, and a horizontal
    scan counts distinct destinations on the SAME port. In v2 a normal browsing
    host reached 15 distinct destinations over the ~8 minute, 8000-record buffer
    and was flagged. Vertical threshold 10 was fitted on the 1M-sample training split.
    """
    if not records:
        return []

    if window_s is not None:
        latest = max(r.get("timestamp", 0.0) for r in records)
        records = [r for r in records if r.get("timestamp", 0.0) >= latest - window_s]

    src_to_dsts = defaultdict(set)          # (src, port) -> destinations
    src_dst_to_ports = defaultdict(set)
    src_timestamps = defaultdict(list)

    for r in records:
        src = r["src_ip"]
        dst = r["dst_ip"]
        port = r["dst_port"]
        ts = r.get("timestamp", 0.0)

        src_to_dsts[(src, port)].add(dst)
        src_dst_to_ports[(src, dst)].add(port)
        src_timestamps[src].append(ts)

    alerts = []

    def rate(src):
        ts_list = src_timestamps[src]
        duration = max(0.1, max(ts_list) - min(ts_list)) if len(ts_list) > 1 else 1.0
        return len(ts_list) / duration

    for (src, port), dst_set in src_to_dsts.items():
        unique_dsts = len(dst_set)
        if unique_dsts >= horizontal_threshold:
            alerts.append(
                {
                    "src_ip": src,
                    "threat_type": "horizontal_reconnaissance_scan",
                    "alert": True,
                    "confidence": round(
                        min(1.0, unique_dsts / (horizontal_threshold * 2)), 3
                    ),
                    "unique_targets": unique_dsts,
                    "target_port": port,
                    "packet_rate_pps": round(rate(src), 2),
                }
            )

    for (src, dst), ports in src_dst_to_ports.items():
        unique_ports = len(ports)
        if unique_ports >= vertical_threshold:
            alerts.append(
                {
                    "src_ip": src,
                    "target_ip": dst,
                    "threat_type": "vertical_port_scan",
                    "alert": True,
                    "confidence": round(
                        min(1.0, unique_ports / (vertical_threshold * 2)), 3
                    ),
                    "unique_ports_scanned": unique_ports,
                    "packet_rate_pps": round(rate(src), 2),
                }
            )

    return alerts

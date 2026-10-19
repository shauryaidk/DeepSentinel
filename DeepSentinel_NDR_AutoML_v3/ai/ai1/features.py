import numpy as np
import pandas as pd
from entropy_tracker import shannon_entropy
from config import FEATURES


def _percentile(x, q):
    return float(np.percentile(x, q)) if len(x) else 0.0


def _safe_ratio(a, b):
    return float(a / (b + 1e-9))


def build_window_features(flows, window_seconds=10):
    df = flows.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp")
    df["window"] = df["timestamp"].dt.floor(f"{window_seconds}s")

    rows = []
    for window, g in df.groupby("window", sort=True):
        duration = float(window_seconds)
        sizes = g["bytes"].to_numpy(dtype=float) / np.maximum(
            g["packets"].to_numpy(dtype=float), 1
        )

        ingress = float(g.loc[g["direction"].eq("ingress"), "bytes"].sum())
        egress = float(g.loc[g["direction"].eq("egress"), "bytes"].sum())
        total_bytes = float(g["bytes"].sum())
        total_packets = float(g["packets"].sum())
        flow_count = len(g)

        rows.append({
            "timestamp": window,
            "flow_count": flow_count,
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "avg_packet_size": _safe_ratio(total_bytes, total_packets),
            "p95_packet_size": _percentile(sizes, 95),
            "bytes_per_sec": total_bytes / duration,
            "packets_per_sec": total_packets / duration,
            "flow_rate": flow_count / duration,
            "unique_src_ips": g["src_ip"].nunique(),
            "unique_dst_ports": g["dst_port"].nunique(),
            "src_ip_entropy": shannon_entropy(g["src_ip"]),
            "dst_port_entropy": shannon_entropy(g["dst_port"]),
            "packet_size_entropy": shannon_entropy(
                np.clip(np.round(sizes / 16) * 16, 16, None)
            ),
            "ingress_bytes": ingress,
            "egress_bytes": egress,
            "egress_fraction": _safe_ratio(egress, total_bytes),
            "byte_asymmetry_ratio": _safe_ratio(egress, ingress),
        })

    out = pd.DataFrame(rows)
    return out


def select_features(df):
    return df[FEATURES].astype(float)

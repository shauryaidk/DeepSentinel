"""Host-centric 10-second windows for AI-1 (v3).

v2 aggregated every flow on the network into one window and labelled the Zeek
originator's bytes as "egress" whichever side was local. On a real network that
made every window look anomalous and hid a single host's exfiltration inside
everybody else's traffic. v3 builds one window per internal host, with
direction measured from that host:

    egress  = bytes the internal host sent
    ingress = bytes the internal host received
    src_ip  = the remote peer (so unique_src_ips = distinct peers)

The 17 features and their definitions are unchanged (config.FEATURES), and the
same vectorised builder is used for training data and live traffic.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache

import numpy as np
import pandas as pd

from config import DDOS_RULES, EXFIL_RULES, FEATURES, INTERNAL_NETWORKS

_NETS = [ipaddress.ip_network(n) for n in INTERNAL_NETWORKS]


@lru_cache(maxsize=65536)
def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _NETS)


def conn_to_transfers(z: dict) -> list[dict]:
    """A Zeek conn record -> two one-way transfers (orig->resp and resp->orig)."""
    if z.get("ts") is None:
        return []
    ts = float(z["ts"])
    o, r = str(z.get("id.orig_h", "unknown")), str(z.get("id.resp_h", "unknown"))
    port = int(z.get("id.resp_p", 0) or 0)
    return [
        {"timestamp": ts, "src_ip": o, "dst_ip": r, "dst_port": port,
         "bytes": float(z.get("orig_bytes", 0) or 0), "packets": float(z.get("orig_pkts", 0) or 0)},
        {"timestamp": ts, "src_ip": r, "dst_ip": o, "dst_port": port,
         "bytes": float(z.get("resp_bytes", 0) or 0), "packets": float(z.get("resp_pkts", 0) or 0)},
    ]


def host_flows(transfers: pd.DataFrame) -> pd.DataFrame:
    """One-way transfers -> host-centric flow rows (one per internal endpoint)."""
    t = transfers
    src_in = t["src_ip"].map(is_internal).to_numpy()
    dst_in = t["dst_ip"].map(is_internal).to_numpy()
    # If neither side is internal (e.g. a mirror port seeing transit traffic),
    # treat the receiver as the monitored host.
    dst_host = dst_in | ~src_in
    out = pd.concat([
        pd.DataFrame({"host": t["src_ip"][src_in], "peer": t["dst_ip"][src_in],
                      "egress": True}).join(t[["timestamp", "dst_port", "bytes", "packets"]]),
        pd.DataFrame({"host": t["dst_ip"][dst_host], "peer": t["src_ip"][dst_host],
                      "egress": False}).join(t[["timestamp", "dst_port", "bytes", "packets"]]),
    ], ignore_index=True)
    out["packets"] = np.maximum(out["packets"].to_numpy(float), 1.0)
    return out


def _group_entropy(w, key, n_per_w):
    base = int(key.max()) + 1 if len(key) else 1
    k = w.astype(np.int64) * base + key.astype(np.int64)
    uniq, counts = np.unique(k, return_counts=True)
    uw = uniq // base
    p = counts / n_per_w[uw]
    h = np.bincount(uw, weights=-p * np.log2(p), minlength=len(n_per_w))
    distinct = np.bincount(uw, minlength=len(n_per_w))
    return h, distinct


def window_features(w, peer, port, nbytes, packets, egress, m=None, window_seconds=10.0):
    """Vectorised equivalent of features.build_window_features for many windows.

    w: window id per flow row (0..m-1); peer/port: integer codes.
    """
    w = np.asarray(w); m = int(w.max()) + 1 if m is None else m
    nbytes = np.asarray(nbytes, float); packets = np.asarray(packets, float)
    egress = np.asarray(egress, bool)
    d = float(window_seconds)
    n = np.bincount(w, minlength=m).astype(float)
    tb = np.bincount(w, weights=nbytes, minlength=m)
    tp = np.bincount(w, weights=packets, minlength=m)
    sizes = nbytes / np.maximum(packets, 1)
    order = np.lexsort((sizes, w)); s = sizes[order]
    starts = np.concatenate([[0], np.cumsum(n)[:-1]]).astype(np.int64)
    pos = 0.95 * (n - 1); lo = np.floor(pos).astype(np.int64); hi = np.ceil(pos).astype(np.int64)
    p95 = s[starts + lo] + (s[starts + hi] - s[starts + lo]) * (pos - lo)
    src_h, src_u = _group_entropy(w, np.asarray(peer), n)
    port_h, port_u = _group_entropy(w, np.asarray(port), n)
    size_bin = (np.clip(np.round(sizes / 16) * 16, 16, None) / 16).astype(np.int64)
    size_h, _ = _group_entropy(w, size_bin, n)
    eg = np.bincount(w, weights=np.where(egress, nbytes, 0.0), minlength=m)
    ing = np.bincount(w, weights=np.where(egress, 0.0, nbytes), minlength=m)
    return pd.DataFrame({
        "flow_count": n, "total_bytes": tb, "total_packets": tp,
        "avg_packet_size": tb / (tp + 1e-9), "p95_packet_size": p95,
        "bytes_per_sec": tb / d, "packets_per_sec": tp / d, "flow_rate": n / d,
        "unique_src_ips": src_u.astype(float), "unique_dst_ports": port_u.astype(float),
        "src_ip_entropy": src_h, "dst_port_entropy": port_h, "packet_size_entropy": size_h,
        "ingress_bytes": ing, "egress_bytes": eg, "egress_fraction": eg / (tb + 1e-9),
        "byte_asymmetry_ratio": eg / (ing + 1e-9),
    })


def build_host_windows(transfers: pd.DataFrame, window_seconds: int = 10) -> pd.DataFrame:
    """One-way transfers (timestamp in epoch seconds) -> one feature row per (window, host)."""
    if transfers.empty:
        return pd.DataFrame(columns=["timestamp", "host"] + FEATURES)
    f = host_flows(transfers)
    win = np.floor(f["timestamp"].to_numpy(float) / window_seconds) * window_seconds
    key = pd.MultiIndex.from_arrays([win, f["host"].to_numpy()])
    w, uniq = pd.factorize(key, sort=True)
    feats = window_features(w, pd.factorize(f["peer"])[0], pd.factorize(f["dst_port"])[0],
                            f["bytes"], f["packets"], f["egress"], len(uniq), window_seconds)
    feats.insert(0, "host", [h for _, h in uniq])
    feats.insert(0, "timestamp", pd.to_datetime([t for t, _ in uniq], unit="s", utc=True))
    return feats


def classify(row) -> tuple[str | None, list[str]]:
    """Rule check on an anomalous window. Returns (threat or None, reasons)."""
    reasons = []
    inbound_heavy = row["egress_fraction"] <= DDOS_RULES["max_egress_fraction"]
    volume = (row["bytes_per_sec"] >= DDOS_RULES["bytes_per_sec"]
              and row["packets_per_sec"] >= DDOS_RULES["packets_per_sec"])
    distributed = (row["flow_rate"] >= DDOS_RULES["flow_rate"]
                   and row["unique_src_ips"] >= DDOS_RULES["unique_src_ips"])
    if volume:
        reasons.append("very high inbound byte/packet volume")
    if distributed:
        reasons.append("high distributed flow rate and source diversity")
    exfil = (row["egress_fraction"] >= EXFIL_RULES["egress_fraction"]
             and row["byte_asymmetry_ratio"] >= EXFIL_RULES["byte_asymmetry_ratio"]
             and row["egress_bytes"] >= EXFIL_RULES["egress_bytes"]
             and row["unique_src_ips"] <= EXFIL_RULES["max_unique_peers"])
    if exfil:
        reasons.append("strong outbound byte asymmetry")
    if exfil:
        return "possible_exfiltration", reasons
    if inbound_heavy and row["bytes_per_sec"] >= DDOS_RULES["min_bytes_per_sec"] and (volume or distributed):
        return "possible_volumetric_ddos", reasons
    return None, reasons

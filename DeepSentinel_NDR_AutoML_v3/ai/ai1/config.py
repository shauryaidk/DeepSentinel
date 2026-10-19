FEATURES = [
    "flow_count",
    "total_bytes",
    "total_packets",
    "avg_packet_size",
    "p95_packet_size",
    "bytes_per_sec",
    "packets_per_sec",
    "flow_rate",
    "unique_src_ips",
    "unique_dst_ports",
    "src_ip_entropy",
    "dst_port_entropy",
    "packet_size_entropy",
    "ingress_bytes",
    "egress_bytes",
    "egress_fraction",
    "byte_asymmetry_ratio",
]

# Transparent explanation thresholds.
# They are deliberately conservative demo values and should be calibrated on
# the organization's benign baseline.
DDOS_RULES = {
    "bytes_per_sec": 1_000_000,
    "packets_per_sec": 1_000,
    "flow_rate": 20,
    "unique_src_ips": 60,
    # v3: a DDoS window must be inbound-heavy and carry real payload, so busy
    # servers answering many clients (egress-heavy) and zero-byte port scans
    # (handled by AI-3) do not match.
    "max_egress_fraction": 0.5,
    "min_bytes_per_sec": 100_000,
}

EXFIL_RULES = {
    "egress_fraction": 0.90,
    "byte_asymmetry_ratio": 12.0,
    "egress_bytes": 2_000_000,
    # v3: exfiltration goes to a handful of destinations; a server answering
    # many clients is also egress-heavy but talks to many peers.
    "max_unique_peers": 5,
}

# v3: networks treated as "inside" when building host-centric windows.
INTERNAL_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# v3: AI-1 publishes an alert only when the autoencoder flags the window AND a
# DDoS/exfiltration rule confirms it. Unconfirmed anomalies are counted only.

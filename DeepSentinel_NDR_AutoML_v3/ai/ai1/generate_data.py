"""Synthetic host-centric training data for AI-1 (v3).

Each sample is one internal host's 10-second window, built from simulated
connections (every connection gives the host one egress row and one ingress row,
exactly as live Zeek conn records do in host_windows.py).

    python generate_data.py --windows 30000 --output data/windows.csv

Classes:
  benign  idle/active workstations (1-60 conns to 1-30 peers) and servers
          answering 5-50 clients (response-heavy, i.e. egress-heavy)
  ddos    a victim receiving 180-420 connections from 90-220 sources
          (same ranges as v2), inbound-heavy
  exfil   a host sending 100-700 packets of ~1100 bytes per connection to 1-3
          peers, 30-90 connections per window (same ranges as v2)
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from config import FEATURES
from host_windows import window_features

PORTS = np.array([443, 80, 53, 22, 25, 123, 8080, 8443, 993])
CLASSES = ["benign", "ddos", "exfil"]


def _conns(rng, label, m):
    """Per-connection arrays for m windows of one class."""
    if label == "benign":
        kind = rng.choice(3, m, p=[0.6, 0.3, 0.1])  # idle client, active client, server
        n = np.where(kind == 0, rng.integers(1, 15, m), np.where(kind == 1, rng.integers(15, 60, m),
                                                                  rng.integers(10, 150, m)))
        peers = np.where(kind == 0, rng.integers(1, 10, m), np.where(kind == 1, rng.integers(3, 30, m),
                                                                      rng.integers(5, 50, m)))
        nports = np.where(kind == 2, rng.integers(1, 3, m), rng.integers(1, 6, m))
        w = np.repeat(np.arange(m), n); k = kind[w]; tot = len(w)
        req = rng.lognormal(np.log(900), 0.9, tot); resp = rng.lognormal(np.log(15000), 1.2, tot)
        out_b = np.where(k == 2, resp, req); in_b = np.where(k == 2, req, resp)
        out_p = np.maximum(1, out_b // np.where(k == 2, 1200, 600))
        in_p = np.maximum(1, in_b // np.where(k == 2, 600, 1200))
    elif label == "ddos":
        n = rng.integers(180, 420, m); peers = rng.integers(90, 220, m); nports = rng.integers(1, 4, m)
        w = np.repeat(np.arange(m), n); tot = len(w)
        pk = np.maximum(1, rng.poisson(rng.uniform(80, 500, m)[w]))
        size = np.clip(rng.lognormal(np.log(260), 0.35, tot), 60, 1500)
        in_b = pk * size; in_p = pk
        out_b = in_b * rng.uniform(0.05, 0.25, m)[w]; out_p = np.maximum(1, pk // 10)
    else:
        n = rng.integers(30, 90, m); peers = rng.integers(1, 4, m); nports = rng.integers(1, 3, m)
        w = np.repeat(np.arange(m), n); tot = len(w)
        pk = np.maximum(1, rng.poisson(rng.uniform(100, 700, m)[w]))
        size = np.clip(rng.lognormal(np.log(1100), 0.40, tot), 60, 1500)
        out_b = pk * size; out_p = pk
        in_b = pk * 40.0; in_p = np.maximum(1, pk // 20)
    peer = rng.integers(0, peers[w])
    port = PORTS[rng.integers(0, nports[w])]
    return w, peer, port, out_b, out_p, in_b, in_p


def generate_class(rng, label, m, window_seconds=10.0):
    """m host windows of one class -> feature DataFrame."""
    w, peer, port, ob, op, ib, ip = _conns(rng, label, m)
    W = np.concatenate([w, w]); P = np.concatenate([peer, peer]); PT = np.concatenate([port, port])
    B = np.concatenate([ob, ib]).astype(float); PK = np.concatenate([op, ip]).astype(float)
    EG = np.concatenate([np.ones(len(w), bool), np.zeros(len(w), bool)])
    order = np.argsort(W, kind="stable")
    f = window_features(W[order], P[order], PT[order], B[order], PK[order], EG[order], m, window_seconds)
    f["label"] = label
    return f


def generate(windows=30000, seed=42, probs=(0.70, 0.15, 0.15), chunk=20000):
    rng = np.random.default_rng(seed)
    counts = rng.multinomial(windows, probs)
    parts = []
    for label, c in zip(CLASSES, counts):
        for s in range(0, c, chunk):
            parts.append(generate_class(rng, label, min(chunk, c - s)))
    df = pd.concat(parts, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df[FEATURES + ["label"]]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows", type=int, default=30000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", default="data/windows.csv")
    args = ap.parse_args()
    out = generate(args.windows, args.seed)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output, index=False)
    print(f"Wrote {len(out):,} synthetic host windows to {args.output}")
    print(out["label"].value_counts().to_string())

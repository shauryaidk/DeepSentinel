from __future__ import annotations

import asyncio
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
AI1_DIR = BASE_DIR / "ai" / "ai1"
AI2_DIR = BASE_DIR / "ai" / "ai2"

import sys
if str(AI1_DIR) not in sys.path:
    sys.path.insert(0, str(AI1_DIR))
from config import FEATURES
from host_windows import build_host_windows, classify as ai1_classify

if str(BASE_DIR / "ai") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "ai"))
from ai3 import run_temporal_graph_engine


class AutoMLThreatOrchestrator:
    """Live AutoML-style routing and ensemble layer.

    It does not retrain on live traffic. It automatically routes each
    observation to the detector(s) whose input features are available, then
    emits one standardized NDR alert schema.
    """

    def __init__(self, publish: Callable[[dict], Awaitable[None]], ai2_url: str = "http://localhost:8001"):
        self.publish = publish
        self.ai2_url = ai2_url
        self.ai1_artifact = None
        artifact = AI1_DIR / "models" / "autoencoder.joblib"
        if artifact.exists():
            self.ai1_artifact = joblib.load(artifact)

        self.ai1_rows: list[dict] = []
        self.ai3_rows: list[dict] = []
        self.flow_buckets: dict[tuple, dict] = {}
        self.last_ai1 = 0.0
        self.last_ai3 = 0.0
        self.last_ai2: dict[str, float] = {}
        self.ai2_ok = False
        self.processed_packets = 0
        self.detections = {"AI-1": 0, "AI-2": 0, "AI-3": 0}
        self.ai1_unconfirmed = 0

    @staticmethod
    def _iso(ts: float | None = None):
        return datetime.fromtimestamp(ts or time.time(), timezone.utc).isoformat()

    @staticmethod
    def _severity(threat: str, confidence: float) -> str:
        t = threat.lower()
        if any(x in t for x in ("ddos", "exfil", "malware")):
            return "CRITICAL"
        if any(x in t for x in ("c2", "dga", "scan", "recon", "tunnel")):
            return "HIGH"
        return "HIGH" if confidence >= 0.85 else "MEDIUM"

    async def process_packet(self, event: dict[str, Any]):
        self.processed_packets += 1
        src = event.get("source_ip")
        dst = event.get("destination_ip")
        sport = event.get("source_port")
        dport = event.get("destination_port")
        proto = event.get("protocol", "OTHER")
        ts = float(event.get("timestamp", time.time()))
        length = float(event.get("length", 0) or 0)
        direction = event.get("direction", "unknown")

        if src in (None, "—", "unknown") or dst in (None, "—", "unknown"):
            return

        # AI-3: temporal + graph observation.
        self.ai3_rows.append({
            "src_ip": str(src), "dst_ip": str(dst), "dst_port": int(dport or 0), "timestamp": ts,
        })
        self.ai3_rows = self.ai3_rows[-8000:]

        # AI-2: DGA can run directly from DNS metadata.
        domain = event.get("dns_query")
        if domain and len(str(domain)) >= 4:
            # Debounce identical domain/source pairs for 3 seconds.
            key = f"{src}|{domain}"
            now = time.monotonic()
            if now - self.last_ai2.get(key, 0) >= 3:
                self.last_ai2[key] = now
                asyncio.create_task(self._ai2_domain(str(domain), str(src), str(dst), sport, dport or 53))

        # AI-1: convert packets to flow-like 10-second buckets.
        bucket = math.floor(ts / 10.0) * 10.0
        key = (src, dst, sport or 0, dport or 0, proto, direction, bucket)
        row = self.flow_buckets.get(key)
        if row is None:
            row = {
                "timestamp": bucket,
                "bytes": 0.0,
                "packets": 0.0,
                "direction": direction,
                "src_ip": str(src),
                "dst_ip": str(dst),
                "dst_port": int(dport or 0),
            }
            self.flow_buckets[key] = row
        row["bytes"] += length
        row["packets"] += 1.0

        now = time.monotonic()
        current_bucket = math.floor(ts / 10.0) * 10.0
        closed = []
        for k, v in list(self.flow_buckets.items()):
            if k[-1] < current_bucket:
                closed.append(v)
                del self.flow_buckets[k]
        if closed:
            self.ai1_rows.extend(closed)
            self.ai1_rows = self.ai1_rows[-8000:]

        if len(self.ai3_rows) >= 20 and now - self.last_ai3 >= 2:
            self.last_ai3 = now
            asyncio.create_task(self._run_ai3(list(self.ai3_rows)))

        if len(self.ai1_rows) >= 8 and now - self.last_ai1 >= 2:
            self.last_ai1 = now
            asyncio.create_task(self._run_ai1(list(self.ai1_rows)))

    async def _run_ai1(self, rows: list[dict]):
        if self.ai1_artifact is None:
            return
        try:
            # v3: host-centric windows with direction measured from the internal
            # host; alert only when the autoencoder AND a confirming rule agree.
            transfers = pd.DataFrame(rows)[["timestamp", "src_ip", "dst_ip", "dst_port", "bytes", "packets"]]
            windows = build_host_windows(transfers, window_seconds=10)
            if windows.empty:
                return
            X = windows[FEATURES].astype(float)
            threshold = float(self.ai1_artifact["threshold"])
            Xs = self.ai1_artifact["scaler"].transform(X)
            errors = np.mean((Xs - self.ai1_artifact["model"].predict(Xs)) ** 2, axis=1)

            for idx, row in enumerate(X.to_dict("records")):
                score = float(errors[idx])
                if score <= threshold:
                    continue
                threat, reasons = ai1_classify(row)
                if threat is None:
                    self.ai1_unconfirmed += 1
                    continue
                host = windows["host"].iloc[idx]
                confidence = min(0.99, max(0.51, score / max(threshold * 8.0, 1e-9)))
                evidence = {
                    "host": host,
                    "anomaly_score": round(score, 6),
                    "threshold": round(threshold, 6),
                    "flow_count": int(row["flow_count"]),
                    "total_bytes": int(row["total_bytes"]),
                    "total_packets": int(row["total_packets"]),
                    "bytes_per_sec": round(float(row["bytes_per_sec"]), 2),
                    "packets_per_sec": round(float(row["packets_per_sec"]), 2),
                    "unique_src_ips": int(row["unique_src_ips"]),
                    "unique_dst_ports": int(row["unique_dst_ports"]),
                    "egress_fraction": round(float(row["egress_fraction"]), 4),
                    "byte_asymmetry_ratio": round(float(row["byte_asymmetry_ratio"]), 3),
                }
                exfil = threat == "possible_exfiltration"
                self.detections["AI-1"] += 1
                await self.publish({
                    "timestamp": pd.Timestamp(windows["timestamp"].iloc[idx]).isoformat(),
                    "source_ip": host if exfil else "multiple",
                    "destination_ip": "multiple" if exfil else host,
                    "threat_type": threat,
                    "confidence": confidence,
                    "severity": self._severity(threat, confidence),
                    "evidence": evidence,
                    "reason": "; ".join(reasons),
                    "engine": "AI-1 • Volume & Flow",
                })
        except Exception as exc:
            print(f"[AI1/LIVE] {exc}")

    async def _run_ai3(self, rows: list[dict]):
        try:
            result = await asyncio.to_thread(run_temporal_graph_engine, rows)
            fallback = rows[-1]
            for r in result.get("alerts", []):
                threat = r.get("threat_type", "temporal_graph_anomaly")
                confidence = float(r.get("confidence", 0.5))
                self.detections["AI-3"] += 1
                await self.publish({
                    "timestamp": self._iso(float(fallback.get("timestamp", time.time()))),
                    "source_ip": r.get("src_ip", fallback.get("src_ip", "unknown")),
                    "destination_ip": r.get("target_ip", fallback.get("dst_ip", "unknown")),
                    "destination_port": fallback.get("dst_port"),
                    "protocol": fallback.get("protocol", "IP"),
                    "threat_type": threat,
                    "confidence": confidence,
                    "severity": self._severity(threat, confidence),
                    "evidence": {k: v for k, v in r.items() if k not in {"alert", "threat_type", "confidence", "src_ip", "target_ip"}},
                    "reason": r.get("reason", "Temporal/graph model detected anomalous communication behavior."),
                    "engine": "AI-3 • Temporal & Graph Dynamics",
                })
        except Exception as exc:
            print(f"[AI3/LIVE] {exc}")

    async def _ai2_domain(self, domain: str, src: str, dst: str, sport: Any, dport: Any):
        result = None
        try:
            # Prefer the deployed AI-2 HTTP service if it is available.
            import httpx
            async with httpx.AsyncClient(timeout=2.5) as client:
                response = await client.post(f"{self.ai2_url}/analyze/domain", json={"domain": domain})
                response.raise_for_status()
                result = response.json().get("result", {})
                self.ai2_ok = True
        except Exception:
            # Fall back to the actual local trained ONNX model.
            try:
                if str(AI2_DIR) not in sys.path:
                    sys.path.insert(0, str(AI2_DIR))
                from threat_c_dga.predict import predict_domain
                result = await asyncio.to_thread(predict_domain, domain)
                self.ai2_ok = not bool(result.get("error"))
            except Exception as exc:
                self.ai2_ok = False
                print(f"[AI2/DGA] unavailable: {exc}")
                return

        try:
            if result and result.get("is_dga"):
                confidence = float(result.get("dga_probability", 0.5))
                self.detections["AI-2"] += 1
                await self.publish({
                    "timestamp": self._iso(),
                    "source_ip": src,
                    "destination_ip": dst,
                    "source_port": sport,
                    "destination_port": dport,
                    "protocol": "DNS",
                    "threat_type": "dga_domain",
                    "confidence": confidence,
                    "severity": "HIGH",
                    "evidence": {"domain": domain, "dga_probability": confidence},
                    "reason": "AI-2 sequence model classified the DNS domain as algorithmically generated.",
                    "engine": "AI-2 • Sequence & Payload Metadata / DGA",
                })
        except Exception as exc:
            print(f"[AI2/DGA] result error: {exc}")

    def status(self):
        return {
            "routing": "AutoML live routing/ensemble",
            "ai1_loaded": self.ai1_artifact is not None,
            "ai2_available": self.ai2_ok,
            "ai3_loaded": True,
            "processed_packets": self.processed_packets,
            "detections": dict(self.detections),
            "ai1_flow_rows": len(self.ai1_rows),
            "ai1_unconfirmed_anomalies": self.ai1_unconfirmed,
            "ai3_observations": len(self.ai3_rows),
            "pending_flow_buckets": len(self.flow_buckets),
        }

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from live_capture import LiveCaptureManager
from threat_orchestrator import AutoMLThreatOrchestrator

try:
    from confluent_kafka import Consumer
except Exception:
    Consumer = None

BASE_DIR = Path(__file__).resolve().parents[1]
AI3_DIR = BASE_DIR / "ai" / "ai3"
AI1_DIR = BASE_DIR / "ai" / "ai1"

import sys
import subprocess
if str(AI1_DIR) not in sys.path:
    sys.path.insert(0, str(AI1_DIR))
from config import FEATURES  # type: ignore
from host_windows import build_host_windows, conn_to_transfers, classify as ai1_classify  # type: ignore
import joblib
import numpy as np
import pandas as pd

if str(BASE_DIR / "ai") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "ai"))
from ai3 import run_temporal_graph_engine

PCAP_INBOX = BASE_DIR / "data" / "pcap" / "inbox"
PCAP_UPLOAD_LIMIT = 5 * 1024 * 1024 * 1024

app = FastAPI(
    title="DeepSentinel Unified SOC Backend",
    description="Zeek/Kafka ingestion + AI-1/AI-3 local engines + AI-2 service bridge + WebSocket dashboard",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"]
)

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "zeek-events")
KAFKA_GROUP = os.getenv("KAFKA_GROUP", "sih-deepsentinel-unified-v1")
AI2_URL = os.getenv("AI2_URL", "http://localhost:8001")

alerts: deque[dict[str, Any]] = deque(maxlen=500)
clients: set[WebSocket] = set()
seen: set[str] = set()
consumer_task: asyncio.Task | None = None
started_at = time.time()

# Rolling buffers for the original AI-1/AI-3 logic.
flow_buffer: deque[dict] = deque(maxlen=8000)
ai3_buffer: deque[dict] = deque(maxlen=8000)
last_ai1 = 0.0
last_ai3 = 0.0
last_event_ts = 0.0
ai2_last_ok = False
live_capture = LiveCaptureManager(BASE_DIR / "data" / "pcap" / "live")
threat_orchestrator: AutoMLThreatOrchestrator | None = None

ARTIFACT_PATH = AI1_DIR / "models" / "autoencoder.joblib"
AI1_ARTIFACT = joblib.load(ARTIFACT_PATH) if ARTIFACT_PATH.exists() else None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def severity_for(threat: str, confidence: float) -> str:
    t = threat.lower()
    if any(k in t for k in ("ddos", "exfil", "malware")):
        return "CRITICAL"
    if any(k in t for k in ("c2", "dga", "scan", "recon", "tunnel")):
        return "HIGH"
    return "MEDIUM" if confidence < 0.85 else "HIGH"


def normalize_event(raw: dict[str, Any], default_engine: str = "DeepSentinel") -> dict[str, Any]:
    z = raw.get("zeek", raw)
    threat = raw.get("threat_type") or raw.get("predicted_threat") or raw.get("threat") or raw.get("alert") or raw.get("event_type") or "network_event"
    if isinstance(threat, bool):
        threat = raw.get("event_type", "network_event")
    confidence = float(raw.get("confidence", raw.get("dga_probability", raw.get("malicious_probability", 0.0))) or 0.0)
    if confidence > 1:
        confidence /= 100.0
    return {
        "event_id": raw.get("event_id") or raw.get("id") or f"evt-{int(time.time()*1000)}",
        "timestamp": raw.get("timestamp") or raw.get("ingested_at") or now_iso(),
        "source_ip": z.get("id.orig_h") or z.get("src_ip") or raw.get("source_ip") or raw.get("source") or "unknown",
        "destination_ip": z.get("id.resp_h") or z.get("dst_ip") or raw.get("destination_ip") or raw.get("destination") or "unknown",
        "source_port": z.get("id.orig_p", raw.get("source_port")),
        "destination_port": z.get("id.resp_p", raw.get("destination_port")),
        "protocol": z.get("proto") or raw.get("protocol") or z.get("service") or "—",
        "threat_type": str(threat),
        "severity": str(raw.get("severity") or severity_for(str(threat), confidence)).upper(),
        "confidence": round(max(0.0, min(1.0, confidence)), 4),
        "evidence": raw.get("evidence") or raw.get("metadata") or {},
        "reason": raw.get("reason") or raw.get("explanation") or "",
        "engine": raw.get("engine") or default_engine,
    }


def dedupe_key(a: dict[str, Any]) -> str:
    raw = json.dumps({k: a.get(k) for k in ("timestamp","source_ip","destination_ip","threat_type","engine","evidence")}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


async def broadcast(alert: dict[str, Any]) -> None:
    dead = []
    for ws in list(clients):
        try:
            await ws.send_json(alert)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


async def publish(alert: dict[str, Any]) -> None:
    alert = normalize_event(alert, alert.get("engine", "DeepSentinel"))
    key = dedupe_key(alert)
    if key in seen:
        return
    seen.add(key)
    alerts.appendleft(alert)
    await broadcast(alert)


# Automated ML routing/ensemble layer for live packets.
threat_orchestrator = AutoMLThreatOrchestrator(publish, AI2_URL)


def ai1_analyze(transfers: list[dict]) -> list[dict]:
    """v3: host-centric windows; alert only when the autoencoder flags a window
    and a DDoS/exfiltration rule confirms it (see ai/ai1/host_windows.py)."""
    if AI1_ARTIFACT is None or not transfers:
        return []
    windows = build_host_windows(pd.DataFrame(transfers))
    if windows.empty:
        return []
    X = windows[FEATURES].astype(float)
    Xs = AI1_ARTIFACT["scaler"].transform(X)
    errors = np.mean((Xs - AI1_ARTIFACT["model"].predict(Xs)) ** 2, axis=1)
    threshold = AI1_ARTIFACT["threshold"]
    out = []
    for i, row in enumerate(X.to_dict("records")):
        score = float(errors[i])
        if score <= threshold:
            continue
        threat, reasons = ai1_classify(row)
        if threat is None:
            continue
        conf = min(0.99, max(0.50, score / (threshold * 3.0 + 1e-9)))
        out.append({
            "timestamp": pd.Timestamp(windows["timestamp"].iloc[i]).isoformat(),
            "host": windows["host"].iloc[i],
            "threat_type": threat,
            "confidence": conf,
            "reason": "; ".join(reasons),
            "evidence": {
                "host": windows["host"].iloc[i],
                "flow_count": int(row["flow_count"]),
                "total_bytes": float(row["total_bytes"]),
                "total_packets": float(row["total_packets"]),
                "bytes_per_sec": float(row["bytes_per_sec"]),
                "packets_per_sec": float(row["packets_per_sec"]),
                "unique_src_ips": int(row["unique_src_ips"]),
                "unique_dst_ports": int(row["unique_dst_ports"]),
                "egress_bytes": float(row["egress_bytes"]),
                "egress_fraction": float(row["egress_fraction"]),
                "byte_asymmetry_ratio": float(row["byte_asymmetry_ratio"]),
                "anomaly_score": score,
            },
            "engine": "AI-1 • Volume & Flow",
        })
    return out


def event_to_flow(z: dict) -> list[dict]:
    return conn_to_transfers(z)


def event_to_ai3(z: dict) -> dict | None:
    if not all(k in z for k in ("ts","id.orig_h","id.resp_h","id.resp_p")):
        return None
    return {"src_ip": z["id.orig_h"], "dst_ip": z["id.resp_h"], "dst_port": int(z.get("id.resp_p",0) or 0), "timestamp": float(z["ts"])}


def format_ai1(r: dict) -> dict:
    exfil = r.get("threat_type") == "possible_exfiltration"
    return {
        "timestamp": r.get("timestamp"),
        "source_ip": r.get("host", "unknown") if exfil else "multiple",
        "destination_ip": "multiple" if exfil else r.get("host", "unknown"),
        "threat_type": r.get("threat_type","other_anomaly"),
        "confidence": r.get("confidence",0.5),
        "evidence": r.get("evidence",{}),
        "reason": r.get("reason"),
        "engine": r.get("engine","AI-1 • Volume & Flow"),
    }


def format_ai3(r: dict, fallback: dict) -> dict:
    return {
        "timestamp": datetime.fromtimestamp(float(fallback.get("timestamp", time.time())), timezone.utc).isoformat(),
        "source_ip": r.get("src_ip") or fallback.get("src_ip") or "unknown",
        "destination_ip": r.get("target_ip") or fallback.get("dst_ip") or "unknown",
        "destination_port": fallback.get("dst_port"),
        "protocol": "TCP",
        "threat_type": r.get("threat_type","temporal_graph_anomaly"),
        "confidence": float(r.get("confidence",0.5)),
        "evidence": {k:v for k,v in r.items() if k not in {"alert","threat_type","confidence","src_ip","target_ip"}},
        "reason": r.get("reason","Temporal/graph anomaly detected."),
        "engine": "AI-3 • Temporal & Graph Dynamics",
    }


async def ai2_domain(domain: str, raw: dict) -> None:
    global ai2_last_ok
    if not domain:
        return
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            res = await client.post(f"{AI2_URL}/analyze/domain", json={"domain":domain})
        res.raise_for_status()
        ai2_last_ok = True
        result = res.json().get("result", {})
        if result.get("is_dga"):
            await publish({
                "source_ip": raw.get("id.orig_h","unknown"), "destination_ip": raw.get("id.resp_h","unknown"),
                "source_port": raw.get("id.orig_p"), "destination_port": raw.get("id.resp_p",53), "protocol": "DNS",
                "threat_type": "dga", "confidence": result.get("dga_probability",0.0),
                "evidence": {"domain": domain, "dga_probability": result.get("dga_probability")},
                "reason": "AI-2 DGA sequence model classified the DNS domain as algorithmically generated.",
                "engine": "AI-2 • Sequence & Payload Metadata / DGA",
            })
    except Exception as exc:
        ai2_last_ok = False
        print(f"[AI2] {exc}")


async def ai2_session(z: dict) -> None:
    global ai2_last_ok
    ja4 = z.get("ja4") or z.get("ja4_fingerprint")
    if not ja4:
        return
    try:
        payload = {
            "bytes_in": float(z.get("resp_bytes",0) or 0),
            "bytes_out": float(z.get("orig_bytes",0) or 0),
            "duration_ms": max(float(z.get("duration",0.001))*1000.0, 0.001),
            "packet_count": max(1, int((z.get("orig_pkts",0) or 0)+(z.get("resp_pkts",0) or 0))),
            "ja4_fingerprint": str(ja4),
            "inter_arrival_variance": float(z.get("inter_arrival_variance",10.0) or 0.0),
        }
        async with httpx.AsyncClient(timeout=3.0) as client:
            res = await client.post(f"{AI2_URL}/analyze/session", json=payload)
        res.raise_for_status()
        ai2_last_ok = True
        result = res.json().get("result", {})
        if result.get("is_malicious"):
            await publish({
                "source_ip": z.get("id.orig_h","unknown"), "destination_ip": z.get("id.resp_h","unknown"),
                "source_port": z.get("id.orig_p"), "destination_port": z.get("id.resp_p"), "protocol": z.get("proto","TCP"),
                "threat_type": "encrypted_malware_session", "confidence": result.get("malicious_probability",0.0),
                "evidence": result, "reason": result.get("explanation","AI-2 session detector flagged this flow."),
                "engine": "AI-2 • Sequence & Payload Metadata / JA4",
            })
    except Exception as exc:
        ai2_last_ok = False
        print(f"[AI2/JA4] {exc}")


async def process_zeek(envelope: dict) -> None:
    global last_ai1, last_ai3, last_event_ts
    z = envelope.get("zeek", envelope)
    last_event_ts = time.time()
    if envelope.get("event_type") == "conn":
        flow_buffer.extend(event_to_flow(z))
        rec = event_to_ai3(z)
        if rec:
            ai3_buffer.append(rec)
        asyncio.create_task(ai2_session(z))
    elif envelope.get("event_type") == "dns":
        asyncio.create_task(ai2_domain(str(z.get("query", "")), z))

    now = time.monotonic()
    if len(flow_buffer) >= 12 and now-last_ai1 >= 2.0:
        last_ai1 = now
        results = await asyncio.to_thread(ai1_analyze, list(flow_buffer))
        for r in results:
            await publish(format_ai1(r))

    if len(ai3_buffer) >= 12 and now-last_ai3 >= 2.0:
        last_ai3 = now
        records = list(ai3_buffer)
        result = await asyncio.to_thread(run_temporal_graph_engine, records)
        for r in result.get("alerts", []):
            await publish(format_ai3(r, records[-1]))


async def kafka_loop() -> None:
    if Consumer is None:
        print("[KAFKA] confluent-kafka is not installed; HTTP/WebSocket mode remains available.")
        return
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": KAFKA_GROUP,
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
    })
    consumer.subscribe([KAFKA_TOPIC])
    print(f"[KAFKA] listening on {KAFKA_TOPIC} @ {KAFKA_BOOTSTRAP}")
    try:
        while True:
            msg = await asyncio.to_thread(consumer.poll, 0.5)
            if msg is None:
                continue
            if msg.error():
                print("[KAFKA]", msg.error())
                continue
            try:
                payload = json.loads(msg.value().decode("utf-8"))
            except Exception:
                continue
            await process_zeek(payload)
            if payload.get("threat_type") or payload.get("predicted_threat"):
                await publish(payload)
    except asyncio.CancelledError:
        pass
    finally:
        consumer.close()


@app.on_event("startup")
async def startup() -> None:
    global consumer_task
    consumer_task = asyncio.create_task(kafka_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    if consumer_task:
        consumer_task.cancel()


@app.get("/")
async def root():
    return {"status":"online", "service":"DeepSentinel Unified SOC", "engines":["AI-1","AI-2","AI-3"]}


@app.get("/api/health")
async def health():
    return {"status":"healthy", "uptime_sec": round(time.time()-started_at,1), "kafka": Consumer is not None}


@app.get("/api/ai/status")
async def ai_status():
    ai2_ok = False
    try:
        async with httpx.AsyncClient(timeout=0.8) as client:
            r = await client.get(f"{AI2_URL}/")
            ai2_ok = r.is_success
    except Exception:
        ai2_ok = False
    return {
        "AI-1": bool(AI1_ARTIFACT),
        "AI-2": ai2_ok or ai2_last_ok,
        "AI-3": True,
    }




@app.get("/api/ingest/status")
async def ingest_status():
    files = []
    PCAP_INBOX.mkdir(parents=True, exist_ok=True)
    for p in sorted(PCAP_INBOX.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True) if PCAP_INBOX.exists() else []:
        if p.is_file():
            files.append({"name": p.name, "size_bytes": p.stat().st_size, "modified": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat()})
    return {"inbox": files[:20]}


def launch_pcap_pipeline(pcap_path: Path) -> None:
    cmd = [sys.executable, str(BASE_DIR / "ingestion" / "pipeline.py"), "--pcap", str(pcap_path)]
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, creationflags=creationflags)


@app.post("/api/ingest/pcap")
async def ingest_pcap(file: UploadFile = File(...)):
    name = Path(file.filename or "upload.pcapng").name
    suffix = Path(name).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .cap files are supported.")
    PCAP_INBOX.mkdir(parents=True, exist_ok=True)
    target = PCAP_INBOX / name
    if target.exists():
        target = PCAP_INBOX / f"{target.stem}_{int(time.time())}{target.suffix}"
    total = 0
    with target.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > PCAP_UPLOAD_LIMIT:
                target.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="PCAP exceeds the 5 GB prototype limit.")
            out.write(chunk)
    launch_pcap_pipeline(target)
    return {"status": "processing", "filename": target.name, "size_bytes": total, "pipeline": "pcap -> zeek -> kafka -> ai -> websocket"}


@app.post("/api/ingest/sample")
async def ingest_sample(kind: str = Query("ddos")):
    samples = {
        "ddos": BASE_DIR / "data" / "pcap" / "processed" / "test.pcapng",
        "default": BASE_DIR / "data" / "pcap" / "processed" / "test.pcapng",
    }
    src = samples.get(kind, samples["default"])
    if not src.exists():
        raise HTTPException(status_code=404, detail="Sample PCAP not found.")
    PCAP_INBOX.mkdir(parents=True, exist_ok=True)
    target = PCAP_INBOX / f"sample_{kind}_{int(time.time())}.pcapng"
    target.write_bytes(src.read_bytes())
    launch_pcap_pipeline(target)
    return {"status": "processing", "filename": target.name, "size_bytes": target.stat().st_size, "pipeline": "pcap -> zeek -> kafka -> ai -> websocket"}




async def publish_live_packet(event: dict[str, Any]) -> None:
    # Traffic is telemetry, not an alert: broadcast it directly to React.
    await broadcast({"type": "traffic", **event})
    if threat_orchestrator is not None:
        await threat_orchestrator.process_packet(event)


@app.get("/api/live/interfaces")
async def live_interfaces():
    return {"interfaces": live_capture.interfaces(), "running": live_capture.running, "interface": live_capture.interface}


@app.get("/api/live/status")
async def live_status():
    return live_capture.status()


@app.post("/api/live/start")
async def live_start(payload: dict[str, Any] | None = None):
    payload = payload or {}
    iface = payload.get("interface")
    if not iface:
        raise HTTPException(status_code=400, detail="Choose a network interface first.")
    try:
        result = live_capture.start(iface, lambda event: asyncio.create_task(publish_live_packet(event)))
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/live/stop")
async def live_stop():
    return live_capture.stop()

@app.get("/api/alerts")
async def get_alerts(limit: int=50):
    return list(alerts)[: max(1,min(limit,500))]


@app.get("/api/dashboard/stats")
async def dashboard_stats():
    counts = Counter(a["severity"] for a in alerts)
    avg = sum(float(a.get("confidence",0)) for a in alerts)/len(alerts) if alerts else 0
    return {
        "monitored_flows": len(flow_buffer),
        "threats_detected": len(alerts),
        "critical": counts.get("CRITICAL",0),
        "high": counts.get("HIGH",0),
        "medium": counts.get("MEDIUM",0),
        "low": counts.get("LOW",0),
        "avg_confidence": round(avg,4),
        "last_event": last_event_ts,
    }


@app.post("/api/alerts")
async def ingest_alert(payload: dict[str,Any]):
    await publish(payload)
    return normalize_event(payload)


@app.post("/api/demo/alert")
async def demo_alert(payload: dict[str,Any]):
    await publish(payload)
    return normalize_event(payload)


@app.post("/api/analyze/zeek")
async def analyze_zeek(payload: dict[str,Any]):
    await process_zeek(payload)
    return {"status":"accepted"}


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)
    except Exception:
        clients.discard(ws)

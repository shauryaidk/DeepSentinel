# DeepSentinel NDR — AutoML Live Threat Detection

SIH 26145 prototype: passive, unidirectional network monitoring with live Npcap capture, automated model routing, AI-1/AI-2/AI-3 threat detection, Zeek/Kafka ingestion, and a React SOC dashboard.

## Architecture

Wi-Fi/Ethernet → Npcap/Scapy → Live Metadata → AutoML Threat Orchestrator → AI-1 / AI-2 / AI-3 → standardized NDR alert → WebSocket → React dashboard

Zeek/Kafka remains available for richer flow/session metadata. AI-2 encrypted-session detection requires real JA4/TLS metadata; the system never invents a fingerprint.

## AI routing

- **AI-1:** 10-second flow buckets → benign-trained autoencoder → volumetric DDoS / exfiltration / anomaly evidence.
- **AI-2:** DNS query metadata → DGA sequence model. If a deployed AI-2 HTTP service is unavailable, the backend attempts the local ONNX model directly.
- **AI-2 session:** Zeek `ja4` + flow metadata can be sent to the existing JA4/XGBoost detector.
- **AI-3:** every live packet becomes a source→destination→port temporal/graph observation → C2 beaconing and reconnaissance/port-scan detection.

“AutoML” here means automatic live routing/ensemble of the already-trained detectors. It intentionally does **not** retrain models on live traffic.

## Backend

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Windows requires Npcap. The backend explicitly enables Scapy libpcap/Npcap with `conf.use_pcap = True`.

## React frontend

```powershell
cd frontend-react
npm install
npm run dev
```

Open the URL printed by Vite, normally `http://localhost:5173` or the next free port.

## Live test

1. Start the backend.
2. Start the React frontend.
3. Select the physical Wi-Fi/Ethernet adapter.
4. Click **Start Capture**.
5. Browse normally or run `ping google.com`.
6. Watch packet telemetry and the AI engine counters.

Normal traffic should generally produce no threat alerts. For a repeatable SIH demonstration, use a controlled/synthetic telemetry test rather than attacking a real host.

## Alert schema

```json
{
  "event_id": "evt-...",
  "timestamp": "2026-09-09T...Z",
  "source_ip": "192.168.1.10",
  "destination_ip": "203.0.113.20",
  "threat_type": "possible_volumetric_ddos",
  "severity": "CRITICAL",
  "confidence": 0.91,
  "evidence": {},
  "reason": "...",
  "engine": "AI-1 • Volume & Flow"
}
```

## Safety / scope

This is a passive monitoring prototype. It does not send probes, inject packets, decrypt application payloads, or create a return path into a monitored network.

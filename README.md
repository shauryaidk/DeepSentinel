DeepSentinel --- ML-Driven Network Detection & Response
DeepSentinel is a research and Smart India Hackathon (SIH) prototype for
passive network threat detection. It combines network-flow
telemetry, DNS/TLS metadata, machine-learning detectors,
temporal/graph-based heuristics, and a live security-operations
dashboard into one monitoring pipeline.
Safety by design: DeepSentinel is intended for defensive
monitoring on networks you own or are explicitly authorized to assess.
Its live capture path records packet metadata; it does not inject
packets, send probes, decrypt application payloads, or create a return
path into the monitored network.

Highlights
- Unified threat orchestration: Routes telemetry to multiple
  detection engines and normalizes findings into a common alert
  format.
- AI-1 --- Volume & Flow: Host-specific 10-second windows, a
  benign-trained autoencoder, and confirmation rules for volumetric
  DDoS and possible exfiltration patterns.
- AI-2 --- Domain & TLS Session: BiLSTM + attention for
  domain-generation-algorithm (DGA) domains, plus an XGBoost detector
  for JA4/TLS session metadata.
- AI-3 --- Temporal & Graph: Looks for command-and-control (C2)
  beaconing, horizontal scans, and vertical port scans using
  time-windowed communication patterns.
- Streaming ingestion: Zeek metadata and Kafka ingestion are
  supported for a richer event pipeline.
- Live monitoring: FastAPI backend, WebSocket alert broadcasting,
  and a React dashboard.
- Model artifacts included: Pretrained model files are included in
  the repository archive; benchmark scripts can rebuild datasets and
  retrain/evaluate detectors.
Architecture
Wi-Fi / Ethernet
       |
       v
Passive capture (Npcap / Scapy) -----> Zeek connection metadata
       |                                         |
       +--------------------+--------------------+
                            v
                      Kafka topic
                      zeek-events
                            |
                            v
                 FastAPI threat orchestrator
                  /          |          \
                 v           v           v
              AI-1          AI-2        AI-3
           Flow/volume    DGA + JA4   Temporal/graph
                  \          |          /
                   +---------+---------+
                             |
                       Normalized alerts
                             |
                       WebSocket stream
                             |
                             v
                     React SOC dashboard
AutoML clarification: In this project, "AutoML" refers to automated
routing/combination of already-trained detectors at runtime. The live
system does not retrain models on live traffic.
Technology stack
- Languages: Python, JavaScript
- Backend/API: FastAPI, Uvicorn, WebSockets
- ML: scikit-learn, XGBoost, PyTorch, ONNX Runtime, joblib
- Network telemetry: Scapy, Npcap, Zeek
- Streaming: Apache Kafka, confluent-kafka
- Frontend: React, Vite
- Containers: Docker Compose
Repository layout
.
├── DeepSentinel_NDR_AutoML_v3/
│   ├── ai/
│   │   ├── ai1/                 # Flow/volume anomaly detection
│   │   ├── ai2/                 # DGA and JA4/TLS service + models
│   │   └── ai3/                 # Temporal and graph-based detection
│   ├── backend/                 # FastAPI API, capture, orchestration
│   ├── consumer/                # Kafka consumer
│   ├── ingestion/               # Zeek parsing and event publishing
│   ├── frontend-react/          # React/Vite dashboard
│   ├── frontend/                # Lightweight frontend
│   ├── zeek/                    # Zeek configuration
│   ├── data/                    # Sample PCAP and Zeek logs
│   ├── docker-compose.yml       # Kafka service
│   └── run_all.ps1              # Windows launch helper
├── benchmark/                   # Dataset generation and evaluation
├── results/
│   └── METRICS.md               # Detailed benchmark report
└── README.md
Getting started
Prerequisites
- Windows is the most directly supported environment for the included
  live-capture workflow.
- Python 3.11+ is recommended; use a virtual environment.
- Node.js and npm for the React dashboard.
- Docker Desktop for the included Kafka service.
- Npcap installed for live packet capture on Windows.
- Administrator privileges may be required by the operating system to
  capture traffic from a selected adapter.
1. Start the backend and AI services
Open PowerShell in the project directory:
cd DeepSentinel_NDR_AutoML_v3
The helper starts Kafka through Docker Compose, starts the AI-2 HTTP
service on port 8001, and runs the unified backend on port 8000:
.\run_all.ps1
The script expects Docker, Python dependencies, and the required model
artifacts to be available. If you prefer manual setup, use separate
terminals:

Terminal 1 --- Kafka
docker compose up -d
Terminal 2 --- AI-2 service
cd ai\ai2
pip install -r requirements.txt
python -m uvicorn app:app --host 0.0.0.0 --port 8001
Terminal 3 --- API backend
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
API documentation is normally available at http://localhost:8000/docs.
2. Start the React dashboard
In a separate terminal:
cd DeepSentinel_NDR_AutoML_v3\frontend-react
npm install
npm run dev
Open the local URL printed by Vite (normally http://localhost:5173).
3. Try live monitoring
1. Start the backend and frontend.
2. Select the appropriate Wi-Fi/Ethernet adapter in the dashboard.
3. Start capture on a network you own or are authorized to monitor.
4. Generate ordinary traffic, such as browsing a website or pinging a
   permitted host.
5. Review telemetry, detector status, and any generated alerts in the
   dashboard.
For a repeatable demo, prefer the included sample data or controlled
synthetic telemetry instead of generating attacks against real systems.
Note: The live capture workflow depends on Npcap and platform
permissions. Zeek/Kafka enrichment and JA4-based session detection
require the corresponding metadata to be present. Stock Zeek does not
necessarily emit JA4 fields without an additional package or
equivalent enrichment.

Benchmarking and evaluation
The repository includes scripts to generate datasets, train/test
detectors, and write a metrics report.

From the repository root:
pip install numpy pandas pyarrow scikit-learn xgboost torch tldextract joblib onnx onnxruntime shap fastapi uvicorn httpx confluent-kafka websockets scapy
cd benchmark
python build_datasets.py
python run_benchmark.py
The full benchmark can be computationally expensive. For a quick smoke
test, see the options documented in
[`benchmark/README.md`](benchmark/README.md). The generated large
Parquet datasets are not all included in the archive;
build_datasets.py regenerates them with fixed seeds.
Reported results
The included [`results/METRICS.md`](results/METRICS.md) contains
per-threat precision, recall, F1, accuracy, and latency results.
Selected figures from that report:
  Detector              Reported evaluation                         Metric
  AI-1 Volume & Flow    Held-out test windows              0.9998 accuracy

  AI-2 DGA (BiLSTM +    Held-out test                      0.9746 accuracy
  attention)            domains/samples       

  AI-3 Temporal & Graph Default thresholds,                0.9814 accuracy
                        held-out test split   
  Pooled DeepSentinel   2.2M pooled test      0.9910 threat-class micro F1
  v3 engines            samples, as reported  
Interpret these results carefully. Several AI-1, JA4, and AI-3
benchmark classes are synthetically generated from defined
distributions, so their scores measure separation on those generated
distributions and should not be treated as expected real-world detection
rates. The JA4 synthetic benchmark has a feature that strongly encodes
the label. The public DGA and UNSW-NB15 results provide additional
real-data evaluation, but they also have dataset-specific limitations.
Read the complete report and caveats before drawing conclusions.
Alert format
The backend normalizes alerts into a common schema similar to:
{
  "event_id": "evt-...",
  "timestamp": "2026-09-09T00:00:00Z",
  "source_ip": "192.168.1.10",
  "destination_ip": "203.0.113.20",
  "threat_type": "possible_volumetric_ddos",
  "severity": "CRITICAL",
  "confidence": 0.91,
  "evidence": {},
  "reason": "Explanation of the detection",
  "engine": "AI-1 • Volume & Flow"
}
The example is illustrative; actual values depend on the event and
detector.
Limitations
- This is a prototype, not a production-ready NDR/SOC replacement.
- Detection quality depends on telemetry quality, network
  configuration, thresholds, model training data, and deployment
  environment.
- Synthetic benchmark results do not establish real-world
  generalization.
- JA4/TLS session detection requires actual JA4/session metadata from
  the sensor pipeline.
- Live capture and Kafka integration require local services,
  permissions, and correct configuration.
- Validate the system on representative, authorized data before
  relying on its alerts operationally.
Roadmap ideas
- Add repeatable integration tests and CI checks for each engine and
  the end-to-end pipeline.
- Add a documented configuration file for internal networks, Kafka
  topics, and service URLs.
- Evaluate with additional representative datasets and report
  per-class false-positive rates.
- Add authentication and role-based access controls before exposing
  the dashboard beyond localhost.
- Package services with reproducible container builds and health
  checks.
Contributing
Issues and pull requests are welcome. For useful bug reports, include
the operating system, Python version, the detector/service involved,
steps to reproduce, and relevant sanitized logs. Do not upload packet
captures or logs containing private or sensitive information.
License
No license was identified in the supplied project files. Add a LICENSE
file before presenting this repository as open source, and choose a
license that matches your intended use.

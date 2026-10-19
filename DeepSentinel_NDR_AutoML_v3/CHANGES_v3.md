# DeepSentinel v3: what changed and why

v3 fixes the problems the end-to-end test found when mixed traffic went
Zeek → Kafka → backend → AI-1/AI-2/AI-3. All models were retrained on
1,000,000 samples per threat class (see `../benchmark` and `../results`).

## AI-2 DGA (`ai/ai2/threat_c_dga`)
- **Bug:** `predict.py` padded domains to 253 characters, but the ONNX model was exported for 64.
  Every `/analyze/domain` call returned HTTP 500, so no DGA alert could ever fire.
- **Fix:** `tokenizer.MAX_LEN = 64` is used for training, export and inference.
- `train.py` now trains in batches (default batch 512, 4 epochs) and accepts `--dataset` (CSV/Parquet),
  so it scales to millions of domains. The shipped model is trained on 1.6M real domains
  (top-1M list + 30 real malware DGA families).

## AI-2 JA4 session (`ai/ai2/threat_d_ja4`)
- **Bug:** `saved_models/ja4_xgboost.json` had been trained on 6 features (including `ja4_hash`),
  but `predict.py` sends 7. Every `/analyze/session` call returned HTTP 500.
- **Fix:** the model is retrained with the 7 features, and `predict.py` now refuses to start
  with a mismatched model file instead of failing on every request. `train.py` accepts `--dataset`.
- The stale 6-feature `datasets/ja4_metadata.csv` was removed.

## AI-1 Volume & Flow (`ai/ai1`, `backend/main.py`, `backend/threat_orchestrator.py`)
- **Bug 1:** all traffic on the network was pooled into one 10-second window, so on a network with
  ~150 hosts every window looked anomalous, and one host's exfiltration was diluted by everyone else.
- **Bug 2:** the Zeek originator's bytes were always labelled "egress", even when the originator was an
  external attacker (a DDoS flood looked like outbound traffic).
- **Bug 3:** the live-capture path passed epoch seconds to `pd.to_datetime` without `unit="s"`.
- **Fix:** new `host_windows.py` builds one window per internal host (direction measured from that
  host, peers counted as sources), vectorised, and used for training data and both live paths.
  Internal networks are set in `config.INTERNAL_NETWORKS`.
- **Rules:** an alert needs the autoencoder anomaly AND a confirming rule. DDoS must be inbound-heavy
  (`max_egress_fraction`) with real payload (`min_bytes_per_sec`), so busy servers and zero-byte port scans
  do not match. Exfiltration must go to at most `max_unique_peers` destinations, so a busy server
  answering many clients does not match. Unconfirmed anomalies are counted (`ai1_unconfirmed_anomalies` in the orchestrator status),
  not published as alerts.
- `generate_data.py`, `train_autoencoder.py`, `detect.py`, `evaluate.py` and `pipeline.py` now work on host
  windows (`python pipeline.py` still runs the whole demo).

## AI-3 Temporal & Graph (`ai/ai3`, mirrored in `ai/ai2/transformation`)
- **Bug:** horizontal scans were counted over the whole 8000-record buffer (~8 minutes) across all
  ports, so every normal browsing host that reached 15 distinct destinations was flagged.
- **Fix:** scans use only the last 60 s (`window_s`) and count distinct destinations per port.
  Vertical threshold is 10 ports (fitted on the 1M-sample training split).
- **Bug:** beacon detection pooled all of a host's traffic, flagging bursty browsing and DDoS bots.
- **Fix:** beacons are detected per (internal source, destination) pair; SNR threshold 10 and jitter
  CV 0.5 were fitted on the 1M-sample training split.

## Still required from the sensor
- The JA4 detector needs `ja4` (and ideally `inter_arrival_variance`) on conn records. Stock Zeek does
  not emit them; add the JA4 Zeek package (or equivalent) or the session detector never runs.

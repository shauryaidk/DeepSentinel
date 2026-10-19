"""Score host windows with the AI-1 autoencoder + confirming rules (v3).

    python detect.py --input data/windows.csv --output data/detections.csv
"""
import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from config import FEATURES
from host_windows import classify


def score_windows(artifact, windows: pd.DataFrame) -> pd.DataFrame:
    X = windows[FEATURES].astype(float)
    Xs = artifact["scaler"].transform(X)
    errors = np.mean((Xs - artifact["model"].predict(Xs)) ** 2, axis=1)
    out = windows.copy()
    out["anomaly_score"] = errors
    out["is_anomaly"] = errors > artifact["threshold"]
    threats, reasons = [], []
    for row, anom in zip(X.to_dict("records"), out["is_anomaly"]):
        t, r = classify(row) if anom else (None, [])
        threats.append(t or "benign"); reasons.append("; ".join(r))
    out["predicted_threat"] = threats
    out["explanation"] = reasons
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/windows.csv")
    ap.add_argument("--model", default="models/autoencoder.joblib")
    ap.add_argument("--output", default="data/detections.csv")
    args = ap.parse_args()
    windows = pd.read_parquet(args.input) if args.input.endswith(".parquet") else pd.read_csv(args.input)
    out = score_windows(joblib.load(args.model), windows)
    if "label" in out:
        out["true_label"] = out["label"]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output, index=False)
    print(out["predicted_threat"].value_counts())
    print(f"Saved detections: {args.output}")


if __name__ == "__main__":
    main()

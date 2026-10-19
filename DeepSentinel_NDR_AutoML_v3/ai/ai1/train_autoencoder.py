"""Train the AI-1 benign-only autoencoder on host windows (v3).

    python train_autoencoder.py --input data/windows.csv --model models/autoencoder.joblib

Input: a windows file from generate_data.py (FEATURES + label), or any baseline
capture turned into host windows with host_windows.build_host_windows. Only
benign rows are used for training.
"""
import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import RobustScaler

from config import FEATURES


def reconstruction_errors(model, X):
    pred = model.predict(X)
    return np.mean((X - pred) ** 2, axis=1)


def train(benign: pd.DataFrame, max_rows=200_000, seed=42):
    X = benign[FEATURES].astype(float).iloc[:max_rows]
    split = max(1, int(len(X) * 0.80))
    scaler = RobustScaler()
    X_train_s = scaler.fit_transform(X.iloc[:split]); X_val_s = scaler.transform(X.iloc[split:])
    model = MLPRegressor(hidden_layer_sizes=(32, 16, 8, 16, 32), activation="relu", solver="adam",
                         learning_rate_init=0.001, batch_size=32, max_iter=150, early_stopping=True,
                         validation_fraction=0.15, random_state=seed, n_iter_no_change=20)
    model.fit(X_train_s, X_train_s)
    val_errors = reconstruction_errors(model, X_val_s)
    return {
        "model": model, "scaler": scaler,
        "threshold": float(np.percentile(val_errors, 95)),
        "features": FEATURES, "window_seconds": 10, "view": "host",
        "n_train": int(split), "n_val": int(len(X) - split),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/windows.csv")
    ap.add_argument("--model", default="models/autoencoder.joblib")
    ap.add_argument("--max-rows", type=int, default=200_000)
    args = ap.parse_args()
    df = pd.read_parquet(args.input) if args.input.endswith(".parquet") else pd.read_csv(args.input)
    art = train(df[df["label"] == "benign"], args.max_rows)
    Path(args.model).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(art, args.model)
    print(f"Training windows: {art['n_train']:,}  validation: {art['n_val']:,}")
    print(f"95th percentile anomaly threshold: {art['threshold']:.6f}")
    print(f"Saved model: {args.model}")


if __name__ == "__main__":
    main()

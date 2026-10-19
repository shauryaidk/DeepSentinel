import os
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split

def classify_ja4_browser(ja4_string: str) -> int:
    """Explicit binary feature: 1 if standard browser TLS signature, 0 if custom script/malware."""
    known_browsers = ["t13d1516h2_", "t13d1716h2_", "t13d1517h2_"]
    return 1 if any(ja4_string.startswith(b) for b in known_browsers) else 0

def load_or_create_ja4_dataset(csv_path):
    if not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0:
        np.random.seed(42)
        n_samples = 300

        # Benign traffic profile (Browsers, stable intervals)
        benign_bytes_in = np.random.normal(5000, 1500, n_samples // 2)
        benign_bytes_out = np.random.normal(2500, 800, n_samples // 2)
        benign_is_browser = np.ones(n_samples // 2)
        benign_jitter = np.random.normal(15.0, 3.0, n_samples // 2) # High variance/random web usage
        benign_labels = np.zeros(n_samples // 2)

        # Malicious C2 profile (Custom sockets, rhythmic beacon jitter)
        mal_bytes_in = np.random.normal(800, 300, n_samples // 2)
        mal_bytes_out = np.random.normal(15000, 4000, n_samples // 2)
        mal_is_browser = np.zeros(n_samples // 2)
        mal_jitter = np.random.uniform(0.1, 1.2, n_samples // 2) # Extremely low variance (robotic beacon rhythm)
        mal_labels = np.ones(n_samples // 2)

        bytes_in = np.clip(np.concatenate([benign_bytes_in, mal_bytes_in]), 10, None)
        bytes_out = np.clip(np.concatenate([benign_bytes_out, mal_bytes_out]), 10, None)

        df = pd.DataFrame({
            'bytes_in': bytes_in,
            'bytes_out': bytes_out,
            'byte_ratio': bytes_out / (bytes_in + 1),
            'duration_ms': np.clip(np.concatenate([np.random.normal(120, 30, n_samples // 2), np.random.normal(15, 5, n_samples // 2)]), 1, None),
            'packet_count': np.clip(np.concatenate([np.random.normal(30, 8, n_samples // 2), np.random.normal(8, 2, n_samples // 2)]), 1, None),
            'is_known_browser': np.concatenate([benign_is_browser, mal_is_browser]),
            'inter_arrival_variance': np.concatenate([benign_jitter, mal_jitter]),
            'is_malicious': np.concatenate([benign_labels, mal_labels])
        })
        df.to_csv(csv_path, index=False)
        return df
    return pd.read_csv(csv_path)

def train_ja4_model(dataset_path=None):
    """v3: optional --dataset (CSV/Parquet with the 7 features + is_malicious or label)."""
    model_save_path = os.path.join("saved_models", "ja4_xgboost.json")
    if dataset_path:
        df = pd.read_parquet(dataset_path) if dataset_path.endswith(".parquet") else pd.read_csv(dataset_path)
        if "is_malicious" not in df:
            df["is_malicious"] = (df["label"] != "benign").astype(int)
    else:
        dataset_path = os.path.join("datasets", "ja4_metadata_v2.csv")
        if os.path.exists(dataset_path):
            os.remove(dataset_path)
        df = load_or_create_ja4_dataset(dataset_path)

    features = ['bytes_in', 'bytes_out', 'byte_ratio', 'duration_ms', 'packet_count', 'is_known_browser', 'inter_arrival_variance']
    X = df[features]
    y = df['is_malicious']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = xgb.XGBClassifier(n_estimators=60, max_depth=4, learning_rate=0.1, eval_metric="logloss")
    print("Training Bulletproof XGBoost model on behavioral metrics & browser signatures...")
    model.fit(X_train, y_train)

    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    model.save_model(model_save_path)
    print(f"Model saved successfully to {model_save_path}")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=None)
    train_ja4_model(ap.parse_args().dataset)
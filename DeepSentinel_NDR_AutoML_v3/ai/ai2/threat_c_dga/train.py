"""Train the BiLSTM-attention DGA model.

    python -m threat_c_dga.train                                  # datasets/dga_domains.csv
    python -m threat_c_dga.train --dataset big.parquet --epochs 4 # 1M+ domains

Dataset columns: domain, is_dga (0/1). CSV or Parquet.
v3: batched, pre-tokenised training so it scales to millions of domains
(v2 used batch size 4 for 40 epochs, which only works for the 14-row demo file).
"""
import argparse
import os

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from threat_c_dga.model import DGALSTM
from threat_c_dga.tokenizer import domain_to_tensor


def load_dataset(path):
    # Fallback to the small demo set if no real dataset is present.
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        df = pd.DataFrame({
            "domain": ["google.com", "wikipedia.org", "github.com", "microsoft.com", "amazon.in", "youtube.com",
                       "reddit.com", "stackoverflow.com", "xeogrhxquuubt.ru", "pqzmwnxyeuq823.cc", "789xczv781.biz",
                       "kjashdf8723kjahsd.info", "vbnmzxcqwepoiuy.org", "18237912hksad.net"],
            "is_dga": [0] * 8 + [1] * 6,
        })
        df.to_csv(path, index=False)
        return df
    df = pd.read_parquet(path) if path.endswith(".parquet") else pd.read_csv(path)
    return df.dropna(subset=["domain", "is_dga"])


def train_dga_model(dataset_path=os.path.join("datasets", "dga_domains.csv"),
                    model_save_path=os.path.join("saved_models", "dga_lstm.pth"),
                    epochs=4, batch_size=512, lr=0.002, seed=42):
    df = load_dataset(dataset_path)
    X = torch.from_numpy(np.stack([domain_to_tensor(str(d)).numpy() for d in df["domain"]]).astype(np.int64))
    y = torch.tensor(df["is_dga"].to_numpy(np.float32)).unsqueeze(1)
    torch.manual_seed(seed)
    model = DGALSTM()
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    bs = min(batch_size, max(1, len(X) // 4))
    print(f"Training BiLSTM-attention on {len(X):,} domains, {epochs} epochs, batch {bs}")
    model.train()
    for epoch in range(epochs):
        perm = torch.randperm(len(X)); total = 0.0; steps = 0
        for i in range(0, len(X), bs):
            b = perm[i:i + bs]
            optimizer.zero_grad()
            loss = criterion(model(X[b]), y[b])
            loss.backward(); optimizer.step()
            total += loss.item(); steps += 1
        print(f"Epoch [{epoch + 1}/{epochs}] - Loss: {total / steps:.4f}")
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    torch.save(model.state_dict(), model_save_path)
    print(f"Saved {model_save_path}; run `python -m threat_c_dga.export_onnx` to refresh the ONNX model")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.join("datasets", "dga_domains.csv"))
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch-size", type=int, default=512)
    a = ap.parse_args()
    train_dga_model(a.dataset, epochs=a.epochs, batch_size=a.batch_size)
